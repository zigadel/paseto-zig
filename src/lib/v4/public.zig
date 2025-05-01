const std = @import("std");
const base64 = std.base64.url_safe_no_pad;
const ed25519 = @import("../crypto/ed25519.zig");
const PasetoError = @import("../errors.zig").PasetoError;

/// Signs a payload using PASETO v4.public (asymmetric, Ed25519).
pub fn signV4Public(
    allocator: std.mem.Allocator,
    keypair: ed25519.KeyPair,
    payload: []const u8,
    footer: ?[]const u8,
) ![]u8 {
    const header = "v4.public";

    const pae = [_][]const u8{ header, payload, footer orelse &.{} };
    const pre_auth = try preAuthEncode(allocator, &pae);
    defer allocator.free(pre_auth);

    const sig = try ed25519.sign(keypair, pre_auth);

    const b64_payload = try base64Encode(allocator, payload);
    defer allocator.free(b64_payload);

    const b64_sig = try base64Encode(allocator, &sig);
    defer allocator.free(b64_sig);

    const base_token = try std.mem.concat(allocator, u8, &[_][]const u8{
        header, ".", b64_payload, ".", b64_sig,
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

/// Verifies a v4.public token using the Ed25519 public key.
pub fn verifyV4Public(
    allocator: std.mem.Allocator,
    public_key: [ed25519.ED25519_PUBLIC_KEY_SIZE]u8,
    token: []const u8,
) !struct { payload: []u8, footer: []u8 } {
    const header = "v4.public";

    if (token.len < header.len or !std.mem.startsWith(u8, token, header))
        return PasetoError.InvalidToken;

    const body = token[header.len + 1 ..];
    const parts = try splitToken(allocator, body);
    errdefer {
        allocator.free(parts.raw);
        allocator.free(parts.payload);
        allocator.free(parts.signature);
        allocator.free(parts.footer);
    }

    const pae = [_][]const u8{ header, parts.payload, parts.footer };
    const pre_auth = try preAuthEncode(allocator, &pae);
    defer allocator.free(pre_auth);

    ed25519.verify(public_key, pre_auth, parts.signature) catch return PasetoError.InvalidToken;

    // clean up internals we’re not returning
    allocator.free(parts.raw);
    allocator.free(parts.signature);

    return .{ .payload = parts.payload, .footer = parts.footer };
}

fn splitToken(allocator: std.mem.Allocator, body: []const u8) !struct {
    raw: []u8,
    payload: []u8,
    signature: []u8,
    footer: []u8,
} {
    const raw = try allocator.dupe(u8, body);

    var it = std.mem.splitSequence(u8, raw, ".");

    const encoded_payload = it.next() orelse {
        allocator.free(raw);
        return PasetoError.InvalidToken;
    };

    const encoded_sig = it.next() orelse {
        allocator.free(raw);
        return PasetoError.InvalidToken;
    };

    const encoded_footer = it.next();
    if (it.next() != null) {
        allocator.free(raw);
        return PasetoError.InvalidToken;
    }

    const payload = base64DecodeAlloc(allocator, encoded_payload) catch {
        allocator.free(raw);
        return PasetoError.InvalidToken;
    };

    const signature = base64DecodeAlloc(allocator, encoded_sig) catch {
        allocator.free(payload);
        allocator.free(raw);
        return PasetoError.InvalidToken;
    };

    const footer = if (encoded_footer) |ef| base64DecodeAlloc(allocator, ef) catch {
        allocator.free(signature);
        allocator.free(payload);
        allocator.free(raw);
        return PasetoError.InvalidToken;
    } else @constCast(&.{});

    return .{ .raw = raw, .payload = payload, .signature = signature, .footer = footer };
}

fn base64Encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const len = base64.Encoder.calcSize(input.len);
    const buf = try allocator.alloc(u8, len);
    _ = base64.Encoder.encode(buf, input);
    return buf;
}

fn base64DecodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const len = try base64.Decoder.calcSizeForSlice(input);
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try base64.Decoder.decode(buf, input);
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

// ------------------ Tests ------------------

test "v4.public roundtrip without footer" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();

    const token = try signV4Public(allocator, keypair, "payload", null);
    defer allocator.free(token);

    const result = try verifyV4Public(allocator, keypair.public_key.toBytes(), token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, result.payload, "payload");
    try std.testing.expectEqualSlices(u8, &.{}, result.footer);
}

test "v4.public reject invalid token header" {
    const allocator = std.testing.allocator;
    const pubkey = ed25519.generateKeypair().public_key.toBytes();

    const bad_token = "v4.private.invalid";
    const result = verifyV4Public(allocator, pubkey, bad_token);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}

test "v4.public reject token with missing parts" {
    const allocator = std.testing.allocator;
    const pubkey = ed25519.generateKeypair().public_key.toBytes();

    const bad_token = "v4.public.";
    const result = verifyV4Public(allocator, pubkey, bad_token);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}

test "v4.public reject token with too many parts" {
    const allocator = std.testing.allocator;
    const pubkey = ed25519.generateKeypair().public_key.toBytes();

    const bad_token = "v4.public.payload.sig.extra";
    const result = verifyV4Public(allocator, pubkey, bad_token);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}

test "v4.public detect signature tampering" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();

    const token = try signV4Public(allocator, keypair, "hello", null);
    defer allocator.free(token);

    const mut = try allocator.dupe(u8, token);
    defer allocator.free(mut);

    // Flip a bit in the signature (after 2nd dot)
    var i: usize = 0;
    var dot_count: usize = 0;
    while (i < mut.len) : (i += 1) {
        if (mut[i] == '.') {
            dot_count += 1;
            if (dot_count == 2 and i + 3 < mut.len) {
                mut[i + 3] ^= 0x04;
                break;
            }
        }
    }

    const result = verifyV4Public(allocator, keypair.public_key.toBytes(), mut);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}

test "v4.public fail if public key is invalid" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();

    const token = try signV4Public(allocator, keypair, "hello", null);
    defer allocator.free(token);

    const bad_pubkey = [_]u8{0xFF} ** ed25519.ED25519_PUBLIC_KEY_SIZE;
    const result = verifyV4Public(allocator, bad_pubkey, token);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}

test "v4.public fail with corrupted footer" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();

    const token = try signV4Public(allocator, keypair, "payload", "footer");
    defer allocator.free(token);

    const mut = try allocator.dupe(u8, token);
    defer allocator.free(mut);

    // Find and corrupt the footer (after last dot)
    var i: usize = mut.len;
    while (i > 0) {
        i -= 1;
        if (mut[i] == '.') {
            if (i + 3 < mut.len) {
                mut[i + 1] = '^';
                mut[i + 2] = '~';
                mut[i + 3] = '!';
            }
            break;
        }
    }

    const result = verifyV4Public(allocator, keypair.public_key.toBytes(), mut);
    try std.testing.expectError(PasetoError.InvalidToken, result);
}

test "v4.public sign/verify empty message" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();

    const token = try signV4Public(allocator, keypair, "", null);
    defer allocator.free(token);

    const result = try verifyV4Public(allocator, keypair.public_key.toBytes(), token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqual(result.payload.len, 0);
    try std.testing.expectEqual(result.footer.len, 0);
}

test "v4.public sign/verify all-zero message" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();

    const payload = [_]u8{0} ** 32;
    const token = try signV4Public(allocator, keypair, &payload, null);
    defer allocator.free(token);

    const result = try verifyV4Public(allocator, keypair.public_key.toBytes(), token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, result.payload, &payload);
    try std.testing.expectEqual(result.footer.len, 0);
}
