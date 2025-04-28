const std = @import("std");
const PasetoError = @import("../errors.zig").PasetoError;
const constants = @import("../constants.zig");

const ChaCha20 = struct {
    state: [16]u32,

    pub fn init(key: []const u8, nonce: []const u8, counter: u32) ChaCha20 {
        var self = ChaCha20{
            .state = undefined,
        };

        self.state[0] = 0x61707865;
        self.state[1] = 0x3320646e;
        self.state[2] = 0x79622d32;
        self.state[3] = 0x6b206574;

        self.state[4] = std.mem.bytesToValue(u32, key[0..4]);
        self.state[5] = std.mem.bytesToValue(u32, key[4..8]);
        self.state[6] = std.mem.bytesToValue(u32, key[8..12]);
        self.state[7] = std.mem.bytesToValue(u32, key[12..16]);
        self.state[8] = std.mem.bytesToValue(u32, key[16..20]);
        self.state[9] = std.mem.bytesToValue(u32, key[20..24]);
        self.state[10] = std.mem.bytesToValue(u32, key[24..28]);
        self.state[11] = std.mem.bytesToValue(u32, key[28..32]);

        self.state[12] = counter;
        self.state[13] = std.mem.bytesToValue(u32, nonce[0..4]);
        self.state[14] = std.mem.bytesToValue(u32, nonce[4..8]);
        self.state[15] = std.mem.bytesToValue(u32, nonce[8..12]);

        return self;
    }

    pub fn xor(self: *ChaCha20, output: []u8, input: []const u8) void {
        var block: [64]u8 = undefined;
        var position: usize = 0;
        var working_state: [16]u32 = undefined;

        while (position < input.len) {
            working_state = self.state;

            // 20 rounds = 10 double rounds
            inline for (0..10) |_| {
                quarterRound(&working_state, 0, 4, 8, 12);
                quarterRound(&working_state, 1, 5, 9, 13);
                quarterRound(&working_state, 2, 6, 10, 14);
                quarterRound(&working_state, 3, 7, 11, 15);

                quarterRound(&working_state, 0, 5, 10, 15);
                quarterRound(&working_state, 1, 6, 11, 12);
                quarterRound(&working_state, 2, 7, 8, 13);
                quarterRound(&working_state, 3, 4, 9, 14);
            }

            for (0..16) |i| {
                working_state[i] +%= self.state[i];
            }

            for (0..16) |i| {
                const out_offset = i * 4;
                writeU32LE(@ptrCast(&block[out_offset]), working_state[i]);
            }

            const remaining = input.len - position;
            const n = @min(remaining, 64);

            @memcpy(output[position .. position + n], input[position .. position + n]);
            for (0..n) |i| {
                output[position + i] ^= block[i];
            }

            position += n;
            self.state[12] +%= 1;
        }
    }
};

/// Encrypts a plaintext with XChaCha20-Poly1305.
/// - `key`: 32 bytes
/// - `nonce`: 24 bytes
/// - `aad`: Additional authenticated data
pub fn encrypt(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    plaintext: []const u8,
) ![]u8 {
    if (key.len != constants.XCHACHA20_KEY_SIZE)
        return PasetoError.InvalidKey;
    if (nonce.len != constants.XCHACHA20_NONCE_SIZE)
        return PasetoError.InvalidNonce;

    const derived_key = try deriveSubkey(key, nonce[0..16]);
    defer zeroize(@constCast(derived_key[0..]));

    const sub_nonce = buildSubnonce(nonce[16..24]);

    const tag_len = constants.POLY1305_TAG_SIZE;
    const ciphertext_len = plaintext.len + tag_len;
    const ciphertext = try allocator.alloc(u8, ciphertext_len);
    errdefer allocator.free(ciphertext);

    // Encrypt plaintext with ChaCha20 (starting at counter 1)
    try encryptChaCha20(derived_key[0..], sub_nonce[0..], 1, plaintext, ciphertext[0..plaintext.len]);

    // Generate Poly1305 key (encrypt empty block at counter 0)
    var poly_key: [32]u8 = undefined;
    try encryptChaCha20(derived_key[0..], sub_nonce[0..], 0, &[_]u8{}, poly_key[0..]);

    // Generate Poly1305 tag
    var tag: [16]u8 = undefined;
    poly1305Auth(
        poly_key[0..],
        aad,
        ciphertext[0..plaintext.len],
        &tag,
    );
    zeroize(poly_key[0..]); // Wipe poly_key immediately after use

    // Append tag after ciphertext
    @memcpy(ciphertext[plaintext.len..], tag[0..]);

    return ciphertext;
}

/// Encrypts a plaintext with XChaCha20-Poly1305 (detached mode).
/// Returns ciphertext and separate authentication tag.
pub fn encryptDetached(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    plaintext: []const u8,
) !struct {
    ciphertext: []u8,
    tag: [16]u8,
} {
    if (key.len != constants.XCHACHA20_KEY_SIZE)
        return PasetoError.InvalidKey;
    if (nonce.len != constants.XCHACHA20_NONCE_SIZE)
        return PasetoError.InvalidNonce;

    const derived_key = try deriveSubkey(key, nonce[0..16]);
    defer zeroize(@constCast(derived_key[0..]));

    const sub_nonce = buildSubnonce(nonce[16..24]);

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ciphertext);

    // Encrypt plaintext with ChaCha20 (starting at counter 1)
    try encryptChaCha20(derived_key[0..], sub_nonce[0..], 1, plaintext, ciphertext);

    // Generate Poly1305 key (encrypt empty block at counter 0)
    var poly_key: [32]u8 = undefined;
    try encryptChaCha20(derived_key[0..], sub_nonce[0..], 0, &[_]u8{}, poly_key[0..]);

    // Generate Poly1305 tag
    var tag: [16]u8 = undefined;
    poly1305Auth(
        poly_key[0..],
        aad,
        ciphertext,
        &tag,
    );

    return .{ .ciphertext = ciphertext, .tag = tag };
}

/// Decrypts a ciphertext with XChaCha20-Poly1305.
/// - `key`: 32 bytes
/// - `nonce`: 24 bytes
/// - `aad`: Additional authenticated data
pub fn decrypt(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    ciphertext: []const u8,
) ![]u8 {
    if (key.len != constants.XCHACHA20_KEY_SIZE)
        return PasetoError.InvalidKey;
    if (nonce.len != constants.XCHACHA20_NONCE_SIZE)
        return PasetoError.InvalidNonce;
    if (ciphertext.len < constants.POLY1305_TAG_SIZE)
        return PasetoError.InvalidToken;

    const derived_key = try deriveSubkey(key, nonce[0..16]);
    defer zeroize(@constCast(derived_key[0..]));

    const sub_nonce = buildSubnonce(nonce[16..24]);

    const ct_len = ciphertext.len - constants.POLY1305_TAG_SIZE;
    const ct = ciphertext[0..ct_len];
    const received_tag = ciphertext[ct_len..];

    if (received_tag.len != constants.POLY1305_TAG_SIZE)
        return PasetoError.InvalidToken;

    const plaintext_len = ct.len;
    const plaintext = try allocator.alloc(u8, plaintext_len);
    errdefer allocator.free(plaintext);

    // Generate Poly1305 key
    var poly_key: [32]u8 = undefined;
    try encryptChaCha20(derived_key[0..], sub_nonce[0..], 0, &[_]u8{}, poly_key[0..]);

    // Verify Poly1305 tag
    var expected_tag: [16]u8 = undefined;
    poly1305Auth(
        poly_key[0..],
        aad,
        ct,
        &expected_tag,
    );
    zeroize(poly_key[0..]); // ✅ Wipe poly_key immediately after use

    const received_tag_array = received_tag[0..16].*;
    const tags_equal = std.crypto.timing_safe.eql([16]u8, received_tag_array, expected_tag);
    zeroize(expected_tag[0..]); // ✅ Wipe expected_tag immediately after use

    if (!tags_equal) {
        return PasetoError.CryptoFailure;
    }

    // Decrypt ciphertext with ChaCha20 (starting at counter 1)
    try encryptChaCha20(derived_key[0..], sub_nonce[0..], 1, ct, plaintext);

    return plaintext;
}

/// Decrypts a ciphertext with XChaCha20-Poly1305 (detached mode).
/// Takes ciphertext and separate authentication tag.
pub fn decryptDetached(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    ciphertext: []const u8,
    tag: [16]u8,
) ![]u8 {
    if (key.len != constants.XCHACHA20_KEY_SIZE)
        return PasetoError.InvalidKey;
    if (nonce.len != constants.XCHACHA20_NONCE_SIZE)
        return PasetoError.InvalidNonce;

    const derived_key = try deriveSubkey(key, nonce[0..16]);
    defer zeroize(@constCast(derived_key[0..]));

    const sub_nonce = buildSubnonce(nonce[16..24]);

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    // Generate Poly1305 key
    var poly_key: [32]u8 = undefined;
    try encryptChaCha20(derived_key[0..], sub_nonce[0..], 0, &[_]u8{}, poly_key[0..]);

    // Verify Poly1305 tag
    var expected_tag: [16]u8 = undefined;
    poly1305Auth(
        poly_key[0..],
        aad,
        ciphertext,
        &expected_tag,
    );

    if (!std.crypto.timing_safe.eql([16]u8, tag, expected_tag)) {
        return PasetoError.CryptoFailure;
    }

    // Decrypt ciphertext with ChaCha20 (starting at counter 1)
    try encryptChaCha20(derived_key[0..], sub_nonce[0..], 1, ciphertext, plaintext);

    return plaintext;
}

fn encryptChaCha20(
    key: []const u8,
    nonce: []const u8,
    initial_counter: u32,
    input: []const u8,
    output: []u8,
) !void {
    var cipher = ChaCha20.init(key, nonce, initial_counter);
    cipher.xor(output, input);
}

fn poly1305Auth(
    key: []const u8,
    aad: []const u8,
    ciphertext: []const u8,
    tag_out: *[16]u8,
) void {
    var poly = std.crypto.onetimeauth.Poly1305.init(@ptrCast(key));

    poly.update(aad);
    const aad_padding = (16 - (aad.len % 16)) % 16;
    if (aad_padding != 0) {
        var pad: [16]u8 = [_]u8{0} ** 16;
        poly.update(pad[0..aad_padding]);
    }

    poly.update(ciphertext);
    const ct_padding = (16 - (ciphertext.len % 16)) % 16;
    if (ct_padding != 0) {
        var pad: [16]u8 = [_]u8{0} ** 16;
        poly.update(pad[0..ct_padding]);
    }

    var length_block: [16]u8 = undefined;
    std.mem.writeInt(u64, @ptrCast(&length_block[0]), aad.len, std.builtin.Endian.little);
    std.mem.writeInt(u64, @ptrCast(&length_block[8]), ciphertext.len, std.builtin.Endian.little);
    poly.update(&length_block);

    poly.final(tag_out);
}

/// Derives a subkey using HChaCha20.
/// Inputs:
/// - 32-byte key
/// - 16-byte nonce slice
fn deriveSubkey(key: []const u8, nonce16: []const u8) ![32]u8 {
    if (key.len != 32 or nonce16.len != 16)
        return PasetoError.InvariantViolation;

    var subkey: [32]u8 = undefined;
    hchacha20(&subkey, nonce16, key);
    return subkey;
}

/// Builds a 12-byte subnonce.
/// - Prefixes 4 bytes of zeros, then appends the last 8 bytes of original nonce.
fn buildSubnonce(last8: []const u8) [12]u8 {
    var nonce: [12]u8 = undefined;

    nonce[0..4].* = .{ 0, 0, 0, 0 };
    @memcpy(nonce[4..12], last8);

    return nonce;
}

/// HChaCha20 Key Derivation.
/// Produces a 32-byte subkey given 32B key and 16B nonce.
fn hchacha20(output: *[32]u8, nonce: []const u8, key: []const u8) void {
    var state: [16]u32 = undefined;

    // Initialize ChaCha20 state constants
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key setup
    state[4] = std.mem.bytesToValue(u32, key[0..4]);
    state[5] = std.mem.bytesToValue(u32, key[4..8]);
    state[6] = std.mem.bytesToValue(u32, key[8..12]);
    state[7] = std.mem.bytesToValue(u32, key[12..16]);
    state[8] = std.mem.bytesToValue(u32, key[16..20]);
    state[9] = std.mem.bytesToValue(u32, key[20..24]);
    state[10] = std.mem.bytesToValue(u32, key[24..28]);
    state[11] = std.mem.bytesToValue(u32, key[28..32]);

    // Nonce setup
    state[12] = std.mem.bytesToValue(u32, nonce[0..4]);
    state[13] = std.mem.bytesToValue(u32, nonce[4..8]);
    state[14] = std.mem.bytesToValue(u32, nonce[8..12]);
    state[15] = std.mem.bytesToValue(u32, nonce[12..16]);

    // Perform 20 ChaCha20 rounds (10 double-rounds)
    for (0..10) |_| {
        quarterRound(&state, 0, 4, 8, 12);
        quarterRound(&state, 1, 5, 9, 13);
        quarterRound(&state, 2, 6, 10, 14);
        quarterRound(&state, 3, 7, 11, 15);

        quarterRound(&state, 0, 5, 10, 15);
        quarterRound(&state, 1, 6, 11, 12);
        quarterRound(&state, 2, 7, 8, 13);
        quarterRound(&state, 3, 4, 9, 14);
    }

    // Output: [0..3] and [12..15]
    writeU32LE(&output[0..4].*, state[0]);
    writeU32LE(&output[4..8].*, state[1]);
    writeU32LE(&output[8..12].*, state[2]);
    writeU32LE(&output[12..16].*, state[3]);
    writeU32LE(&output[16..20].*, state[12]);
    writeU32LE(&output[20..24].*, state[13]);
    writeU32LE(&output[24..28].*, state[14]);
    writeU32LE(&output[28..32].*, state[15]);
}

fn zeroize(buf: []u8) void {
    @memset(buf, 0);
}

/// Performs a ChaCha20 quarter round.
fn quarterRound(state: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
    state[a] = state[a] +% state[b];
    state[d] ^= state[a];
    state[d] = state[d] << 16 | state[d] >> 16;

    state[c] = state[c] +% state[d];
    state[b] ^= state[c];
    state[b] = state[b] << 12 | state[b] >> 20;

    state[a] = state[a] +% state[b];
    state[d] ^= state[a];
    state[d] = state[d] << 8 | state[d] >> 24;

    state[c] = state[c] +% state[d];
    state[b] ^= state[c];
    state[b] = state[b] << 7 | state[b] >> 25;
}

/// Writes a 32-bit little-endian value into a byte slice.
fn writeU32LE(out: *[4]u8, value: u32) void {
    _ = std.mem.writeInt(u32, out, value, std.builtin.Endian.little);
}

test "xchacha20poly1305 encrypt/decrypt roundtrip" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "paseto-zig-test-aad";
    const plaintext = "this is a top secret message";

    const ciphertext = try encrypt(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(ciphertext);

    const decrypted = try decrypt(allocator, &key, &nonce, aad, ciphertext);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "xchacha20poly1305 error on invalid key size" {
    const allocator = std.testing.allocator;
    const key: [31]u8 = undefined; // wrong size
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const aad = "test-aad";
    const plaintext = "test-plaintext";

    const err = encrypt(allocator, &key, &nonce, aad, plaintext);
    try std.testing.expectError(PasetoError.InvalidKey, err);
}

test "xchacha20poly1305 error on invalid nonce size" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    const nonce: [23]u8 = undefined; // wrong size
    std.crypto.random.bytes(&key);
    const aad = "test-aad";
    const plaintext = "test-plaintext";

    const err = encrypt(allocator, &key, &nonce, aad, plaintext);
    try std.testing.expectError(PasetoError.InvalidNonce, err);
}

test "xchacha20poly1305 detect tampered ciphertext" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "test-aad";
    const plaintext = "tamper-detect-test";

    const ciphertext = try encrypt(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(ciphertext);

    // Tamper 1 byte
    var tampered = try allocator.dupe(u8, ciphertext);
    defer allocator.free(tampered);
    tampered[0] ^= 0x01;

    const err = decrypt(allocator, &key, &nonce, aad, tampered);
    try std.testing.expectError(PasetoError.CryptoFailure, err);
}

test "xchacha20poly1305 detect wrong AAD" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "correct-aad";
    const plaintext = "associated-data-test";

    const ciphertext = try encrypt(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(ciphertext);

    const wrong_aad = "wrong-aad";
    const err = decrypt(allocator, &key, &nonce, wrong_aad, ciphertext);
    try std.testing.expectError(PasetoError.CryptoFailure, err);
}

test "xchacha20poly1305 encrypt/decrypt empty plaintext" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "empty-test";
    const plaintext: []const u8 = "";

    const ciphertext = try encrypt(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(ciphertext);

    const decrypted = try decrypt(allocator, &key, &nonce, aad, ciphertext);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "xchacha20poly1305 encrypt/decrypt 1-byte plaintext" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "one-byte-test";
    const plaintext: []const u8 = "A";

    const ciphertext = try encrypt(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(ciphertext);

    const decrypted = try decrypt(allocator, &key, &nonce, aad, ciphertext);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "xchacha20poly1305 encrypt/decrypt large plaintext (~1MB)" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "large-test";
    const large_plaintext = try allocator.alloc(u8, 1024 * 1024); // 1 MB
    defer allocator.free(large_plaintext);

    std.crypto.random.bytes(large_plaintext);

    const ciphertext = try encrypt(allocator, &key, &nonce, aad, large_plaintext);
    defer allocator.free(ciphertext);

    const decrypted = try decrypt(allocator, &key, &nonce, aad, ciphertext);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, large_plaintext, decrypted);
}

test "xchacha20poly1305 reject invalid nonce size" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var invalid_nonce: [10]u8 = undefined; // Invalid: should be 24 bytes
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&invalid_nonce);

    const aad = "invalid-nonce-test";
    const plaintext = "test";

    const result = encrypt(allocator, &key, &invalid_nonce, aad, plaintext);
    try std.testing.expectError(PasetoError.InvalidNonce, result);
}

test "xchacha20poly1305 reject invalid key size" {
    const allocator = std.testing.allocator;

    var invalid_key: [16]u8 = undefined; // Invalid: should be 32 bytes
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&invalid_key);
    std.crypto.random.bytes(&nonce);

    const aad = "invalid-key-test";
    const plaintext = "test";

    const result = encrypt(allocator, &invalid_key, &nonce, aad, plaintext);
    try std.testing.expectError(PasetoError.InvalidKey, result);
}

test "xchacha20poly1305 reject truncated ciphertext (no tag)" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "truncated-test";
    const plaintext = "test";

    const ciphertext = try encrypt(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(ciphertext);

    // Simulate *true* truncated ciphertext (remove *entire* tag or more)
    const truncated = ciphertext[0 .. constants.POLY1305_TAG_SIZE - 1]; // smaller than required
    const result = decrypt(allocator, &key, &nonce, aad, truncated);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}

test "xchacha20poly1305 reject invalid Poly1305 tag (manual tamper)" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "tampered-tag-test";
    const plaintext = "secure message";

    const ciphertext = try encrypt(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(ciphertext);

    var tampered = try allocator.dupe(u8, ciphertext);
    defer allocator.free(tampered);

    tampered[tampered.len - 1] ^= 0x01; // Flip last bit of tag

    const result = decrypt(allocator, &key, &nonce, aad, tampered);
    try std.testing.expectError(PasetoError.CryptoFailure, result);
}

test "xchacha20poly1305 encrypt/decrypt detached roundtrip" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "paseto-zig-detached-test-aad";
    const plaintext = "this is a detached top secret message";

    const result = try encryptDetached(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(result.ciphertext);

    const decrypted = try decryptDetached(allocator, &key, &nonce, aad, result.ciphertext, result.tag);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "xchacha20poly1305 detect tampered detached ciphertext" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "tamper-detached-aad";
    const plaintext = "tamper this message";

    const result = try encryptDetached(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(result.ciphertext);

    var tampered = try allocator.dupe(u8, result.ciphertext);
    defer allocator.free(tampered);

    tampered[0] ^= 0x42; // tamper

    const err = decryptDetached(allocator, &key, &nonce, aad, tampered, result.tag);
    try std.testing.expectError(PasetoError.CryptoFailure, err);
}

test "xchacha20poly1305 detect tampered detached tag" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const aad = "tamper-detached-tag";
    const plaintext = "verify detached tag";

    const result = try encryptDetached(allocator, &key, &nonce, aad, plaintext);
    defer allocator.free(result.ciphertext);

    var tampered_tag = result.tag;
    tampered_tag[0] ^= 0x01; // tamper

    const err = decryptDetached(allocator, &key, &nonce, aad, result.ciphertext, tampered_tag);
    try std.testing.expectError(PasetoError.CryptoFailure, err);
}
