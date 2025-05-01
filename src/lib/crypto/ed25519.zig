const std = @import("std");
const PasetoError = @import("../errors.zig").PasetoError;

pub const Ed25519 = std.crypto.sign.Ed25519;
pub const KeyPair = Ed25519.KeyPair;
pub const PublicKey = Ed25519.PublicKey;
pub const Signature = Ed25519.Signature;

pub const ED25519_PUBLIC_KEY_SIZE = 32;
pub const ED25519_SECRET_KEY_SIZE = 64;
pub const ED25519_SEED_SIZE = 32;
pub const ED25519_SIGNATURE_SIZE = 64;

pub fn generateKeypair() KeyPair {
    return KeyPair.generate();
}

pub fn generateKeypairFromSeed(seed: [ED25519_SEED_SIZE]u8) !KeyPair {
    return KeyPair.generateDeterministic(seed);
}

pub fn sign(keypair: KeyPair, message: []const u8) ![ED25519_SIGNATURE_SIZE]u8 {
    const sig = try keypair.sign(message, null);
    return sig.toBytes();
}

pub fn verify(
    public_key_bytes: [ED25519_PUBLIC_KEY_SIZE]u8,
    message: []const u8,
    signature_bytes: []const u8,
) !void {
    if (signature_bytes.len != ED25519_SIGNATURE_SIZE)
        return PasetoError.InvalidToken;

    const public_key = try PublicKey.fromBytes(public_key_bytes);
    const signature = Signature.fromBytes(signature_bytes[0..64].*);
    try signature.verify(message, public_key);
}

// ---------------------- Tests ----------------------

test "ed25519 key generation, sign, verify roundtrip" {
    const keypair = generateKeypair();
    const message = "test-message";

    const sig = try sign(keypair, message);
    const pubkey = keypair.public_key.toBytes();

    try verify(pubkey, message, &sig);
}

test "ed25519 detect invalid signature" {
    const keypair = generateKeypair();
    const message = "hello world";
    var sig = try sign(keypair, message);

    sig[0] ^= 0x01;

    const pubkey = keypair.public_key.toBytes();
    const result = verify(pubkey, message, &sig);
    try std.testing.expect(result == error.SignatureVerificationFailed or result == error.InvalidEncoding);
}

test "ed25519 error if invalid public key" {
    const bad_pubkey = [_]u8{0xFF} ** ED25519_PUBLIC_KEY_SIZE;
    const message = "bad public key";
    const sig = [_]u8{0xAA} ** ED25519_SIGNATURE_SIZE;

    const result = verify(bad_pubkey, message, &sig);
    try std.testing.expect(result == error.NonCanonical or result == error.IdentityElement);
}

test "ed25519 generate from seed" {
    const seed = [_]u8{0x42} ** ED25519_SEED_SIZE;
    const keypair = try generateKeypairFromSeed(seed);

    const message = "seeded keypair";
    const sig = try sign(keypair, message);
    const pubkey = keypair.public_key.toBytes();

    try verify(pubkey, message, &sig);
}

test "ed25519 sign/verify empty message" {
    const keypair = generateKeypair();
    const message = "";
    const sig = try sign(keypair, message);

    const pubkey = keypair.public_key.toBytes();
    try verify(pubkey, message, &sig);
}

test "ed25519 sign/verify all-zero message" {
    const keypair = generateKeypair();
    const message = [_]u8{0} ** 64;
    const sig = try sign(keypair, &message);

    const pubkey = keypair.public_key.toBytes();
    try verify(pubkey, &message, &sig);
}

test "ed25519 detect signature tampering in scalar (S)" {
    const keypair = generateKeypair();
    const message = "verify me";
    var sig = try sign(keypair, message);

    sig[ED25519_SIGNATURE_SIZE - 1] ^= 0x01;

    const pubkey = keypair.public_key.toBytes();
    const result = verify(pubkey, message, &sig);
    try std.testing.expect(result == error.SignatureVerificationFailed or result == error.InvalidEncoding);
}

test "ed25519 reject short signature" {
    const keypair = generateKeypair();
    const message = "truncate this";
    const sig = try sign(keypair, message);
    const pubkey = keypair.public_key.toBytes();

    var short_sig_fixed: [60]u8 = undefined;
    std.mem.copyForwards(u8, &short_sig_fixed, sig[0..60]);

    const result = verify(pubkey, message, &short_sig_fixed) catch |err| err;
    try std.testing.expectEqual(PasetoError.InvalidToken, result);
}

test "ed25519 verify rejects short signature slice" {
    const keypair = generateKeypair();
    const message = "short sig test";
    const pubkey = keypair.public_key.toBytes();

    const bad_sig = [_]u8{0xAA} ** 60;
    const result = verify(pubkey, message, &bad_sig);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}
