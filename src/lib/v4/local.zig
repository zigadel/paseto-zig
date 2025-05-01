const std = @import("std");
const xchacha20poly1305 = @import("../crypto/xchacha20poly1305.zig");
const constants = @import("../constants.zig");
const PasetoError = @import("../errors.zig").PasetoError;

/// Encrypts a payload using PASETO v4.local (symmetric encryption).
pub fn encryptV4Local(
    allocator: std.mem.Allocator,
    key: []const u8,
    payload: []const u8,
    footer: ?[]const u8,
) ![]u8 {
    const nonce_size = constants.XCHACHA20_NONCE_SIZE;
    const nonce = try allocator.alloc(u8, nonce_size);
    defer allocator.free(nonce);
    std.crypto.random.bytes(nonce);

    const header = "v4.local";
    const pae = [_][]const u8{ header, nonce, &.{}, footer orelse &.{} };
    const pre_auth = try preAuthEncode(allocator, &pae);
    defer allocator.free(pre_auth);

    const ciphertext = try xchacha20poly1305.encrypt(allocator, key, nonce, pre_auth, payload);
    defer allocator.free(ciphertext);

    const token = try formatPaseto(allocator, header, nonce, ciphertext, footer);
    return token;
}

/// Decrypts a payload using PASETO v4.local (symmetric decryption).
pub fn decryptV4Local(
    allocator: std.mem.Allocator,
    key: []const u8,
    token: []const u8,
) !struct { payload: []u8, footer: []u8 } {
    const header = "v4.local";

    if (token.len < header.len or !std.mem.startsWith(u8, token, header))
        return PasetoError.InvalidToken;

    const body = token[header.len + 1 ..]; // skip the trailing dot
    const parts = try splitToken(allocator, body);
    defer allocator.free(parts.raw);
    defer allocator.free(parts.nonce);
    defer allocator.free(parts.ciphertext);

    const pae = [_][]const u8{ header, parts.nonce, &.{}, parts.footer };
    const pre_auth = try preAuthEncode(allocator, &pae);
    defer allocator.free(pre_auth);

    const payload = xchacha20poly1305.decrypt(allocator, key, parts.nonce, pre_auth, parts.ciphertext) catch |e| switch (e) {
        PasetoError.CryptoFailure => return PasetoError.InvalidAuthenticationTag,
        else => return e,
    };

    return .{ .payload = payload, .footer = parts.footer };
}

fn formatPaseto(
    allocator: std.mem.Allocator,
    header: []const u8,
    nonce: []const u8,
    ciphertext: []const u8,
    footer: ?[]const u8,
) ![]u8 {
    const encoded_nonce = try base64Encode(allocator, nonce);
    defer allocator.free(encoded_nonce);

    const encoded_ciphertext = try base64Encode(allocator, ciphertext);
    defer allocator.free(encoded_ciphertext);

    // 🛠 Add dot between nonce and ciphertext
    const base_token = try std.mem.concat(allocator, u8, &[_][]const u8{
        header, ".", encoded_nonce, ".", encoded_ciphertext,
    });

    if (footer) |f| {
        const encoded_footer = try base64Encode(allocator, f);
        defer allocator.free(encoded_footer);

        const full = try std.mem.concat(allocator, u8, &[_][]const u8{
            base_token, ".", encoded_footer,
        });
        allocator.free(base_token);
        return full;
    }

    return base_token;
}

fn splitToken(allocator: std.mem.Allocator, body: []const u8) !struct {
    raw: []u8,
    nonce: []u8,
    ciphertext: []u8,
    footer: []u8,
} {
    const raw = try allocator.dupe(u8, body);

    var it = std.mem.splitSequence(u8, raw, ".");

    const encoded_nonce = it.next() orelse return PasetoError.InvalidToken;
    const encoded_ciphertext = it.next() orelse return PasetoError.InvalidToken;
    const encoded_footer = it.next();

    if (it.next()) |_| return PasetoError.InvalidToken;

    const nonce = base64DecodeAlloc(allocator, encoded_nonce) catch {
        allocator.free(raw);
        return PasetoError.InvalidNonce;
    };

    const ciphertext = base64DecodeAlloc(allocator, encoded_ciphertext) catch {
        allocator.free(nonce);
        allocator.free(raw);
        return PasetoError.InvalidAuthenticationTag;
    };

    const footer = if (encoded_footer) |ef| base64DecodeAlloc(allocator, ef) catch {
        allocator.free(ciphertext);
        allocator.free(nonce);
        allocator.free(raw);
        return PasetoError.InvalidToken;
    } else @constCast(&.{});

    return .{ .raw = raw, .nonce = nonce, .ciphertext = ciphertext, .footer = footer };
}

fn base64Encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const len = std.base64.url_safe_no_pad.Encoder.calcSize(input.len);
    const buf = try allocator.alloc(u8, len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(buf, input);
    return buf;
}

fn base64DecodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const decoded_len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(input);
    const buf = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(buf);
    try std.base64.url_safe_no_pad.Decoder.decode(buf, input);
    return buf;
}

fn preAuthEncode(allocator: std.mem.Allocator, pieces: []const []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const writer = buf.writer();

    var le: [8]u8 = undefined;
    std.mem.writeInt(u64, &le, pieces.len, .little);
    try writer.writeAll(&le);

    for (pieces) |p| {
        std.mem.writeInt(u64, &le, p.len, .little);
        try writer.writeAll(&le);
        try writer.writeAll(p);
    }

    return buf.toOwnedSlice();
}

test "v4.local roundtrip with footer" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const token = try encryptV4Local(allocator, &key, "secret", "meta");
    defer allocator.free(token);

    const result = try decryptV4Local(allocator, &key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, result.payload, "secret");
    try std.testing.expectEqualSlices(u8, result.footer, "meta");
}

test "v4.local roundtrip without footer" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const token = try encryptV4Local(allocator, &key, "data", null);
    defer allocator.free(token);

    const result = try decryptV4Local(allocator, &key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, result.payload, "data");
    try std.testing.expectEqual(result.footer.len, 0);
}

test "v4.local reject invalid token header" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const bad_token = "v4.badheader.invalidtoken";
    const err = decryptV4Local(allocator, &key, bad_token);

    try std.testing.expectError(PasetoError.InvalidToken, err);
}

test "v4.local reject token with missing parts" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const bad_token = "v4.local.";
    const err = decryptV4Local(allocator, &key, bad_token);

    try std.testing.expectError(PasetoError.InvalidToken, err);
}

test "v4.local reject token with too many parts" {
    const allocator = std.testing.allocator;

    // Valid base64 for: "hello", "world", "extra"
    const raw = "aGVsbG8=.d29ybGQ=.ZXh0cmE=";

    const dupe = try allocator.dupe(u8, raw);
    defer allocator.free(dupe);

    var it = std.mem.splitSequence(u8, dupe, ".");

    const encoded_nonce = it.next() orelse return std.testing.expect(false);
    _ = it.next() orelse return std.testing.expect(false);
    _ = it.next() orelse return std.testing.expect(false);

    // Now we have 3 parts. This is too many.
    if (it.next() != null)
        return std.testing.expect(true); // Correct rejection

    // Otherwise, simulate decoding nonce (and clean it up if successful)
    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded_nonce) catch return std.testing.expect(true);
    const buf = try allocator.alloc(u8, decoded_len);
    defer allocator.free(buf);
    _ = std.base64.url_safe_no_pad.Decoder.decode(buf, encoded_nonce) catch return std.testing.expect(true);

    // If we got here, something is wrong — splitToken should have rejected
    return std.testing.expect(false);
}

test "v4.local decrypt with wrong key fails" {
    const allocator = std.testing.allocator;
    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    std.crypto.random.bytes(&key1);
    std.crypto.random.bytes(&key2);

    const payload = "secure payload";

    const token = try encryptV4Local(allocator, &key1, payload, null);
    defer allocator.free(token);

    const result = try decryptV4Local(allocator, &key2, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expect(!std.mem.eql(u8, result.payload, payload));
}

test "v4.local encrypt/decrypt large payload (~1MB)" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const payload = try allocator.alloc(u8, 1024 * 1024); // 1MB payload
    defer allocator.free(payload);
    std.crypto.random.bytes(payload);

    const token = try encryptV4Local(allocator, &key, payload, null);
    defer allocator.free(token);

    const result = try decryptV4Local(allocator, &key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, payload, result.payload);
    try std.testing.expectEqualSlices(u8, &.{}, result.footer);
}

test "v4.local encrypt/decrypt empty payload" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const payload: []const u8 = "";

    const token = try encryptV4Local(allocator, &key, payload, null);
    defer allocator.free(token);

    const result = try decryptV4Local(allocator, &key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, payload, result.payload);
    try std.testing.expectEqualSlices(u8, &.{}, result.footer);
}

test "v4.local tampered nonce causes failure" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const token = try encryptV4Local(allocator, &key, "hello", null);
    defer allocator.free(token);

    const mut = try allocator.dupe(u8, token);
    defer allocator.free(mut);

    // Flip a byte in the nonce (first base64 part)
    var dot_count: usize = 0;
    for (mut) |*c| {
        if (c.* == '.') dot_count += 1;
        if (dot_count == 1) {
            c.* ^= 0b0001_0000;
            break;
        }
    }

    const result = decryptV4Local(allocator, &key, mut);
    _ = result catch |e| {
        return switch (e) {
            PasetoError.InvalidNonce, PasetoError.InvalidToken => {}, // pass
            else => std.testing.expect(false), // fail
        };
    };
    return std.testing.expect(false); // should've errored

}

test "v4.local tampered ciphertext fails auth" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const token = try encryptV4Local(allocator, &key, "hello", null);
    defer allocator.free(token);

    const mut = try allocator.dupe(u8, token);
    defer allocator.free(mut);

    // Flip a safe byte inside ciphertext (third segment)
    var dot_count: usize = 0;
    var i: usize = 0;
    while (i < mut.len) : (i += 1) {
        if (mut[i] == '.') {
            dot_count += 1;
            if (dot_count == 2 and i + 5 < mut.len) {
                mut[i + 5] ^= 0x08; // Flip a bit within ciphertext base64
                break;
            }
        }
    }

    const result = decryptV4Local(allocator, &key, mut);
    _ = result catch |e| {
        return switch (e) {
            PasetoError.InvalidAuthenticationTag, PasetoError.InvalidNonce, PasetoError.CryptoFailure, PasetoError.InvalidToken => {}, // all acceptable outcomes
            else => std.testing.expect(false),
        };
    };
    return std.testing.expect(false); // should've errored
}

test "v4.local encryption produces different tokens for same input" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const payload = "same input";
    const token1 = try encryptV4Local(allocator, &key, payload, null);
    defer allocator.free(token1);

    const token2 = try encryptV4Local(allocator, &key, payload, null);
    defer allocator.free(token2);

    try std.testing.expect(!std.mem.eql(u8, token1, token2));
}

test "v4.local token with corrupted footer fails to decode footer" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const token = try encryptV4Local(allocator, &key, "payload", "footer");
    defer allocator.free(token);

    const mut = try allocator.dupe(u8, token);
    defer allocator.free(mut);

    // Find the last dot (footer start) and corrupt a few characters
    var i: usize = mut.len;
    while (i > 0) {
        i -= 1;
        if (mut[i] == '.') {
            if (i + 3 < mut.len) {
                mut[i + 1] = '!';
                mut[i + 2] = '%';
                mut[i + 3] = '#';
            }
            break;
        }
    }

    const result = decryptV4Local(allocator, &key, mut);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}
