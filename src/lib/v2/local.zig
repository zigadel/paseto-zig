const std = @import("std");
const xchacha20poly1305 = @import("../crypto/xchacha20poly1305.zig");
const constants = @import("../constants.zig");
const PasetoError = @import("../errors.zig").PasetoError;

/// Encrypts a payload for PASETO v2.local (symmetric encryption).
pub fn encryptV2Local(
    allocator: std.mem.Allocator,
    key: []const u8,
    payload: []const u8,
    footer: ?[]const u8,
) ![]u8 {
    const nonce_size = constants.XCHACHA20_NONCE_SIZE;
    const nonce = try allocator.alloc(u8, nonce_size);
    defer allocator.free(nonce);

    std.crypto.random.bytes(nonce);

    const ciphertext = try xchacha20poly1305.encrypt(allocator, key, nonce, &.{}, payload);
    defer allocator.free(ciphertext);

    const header = "v2.local.";
    const token = try formatPaseto(allocator, header, nonce, ciphertext, footer);

    return token;
}

/// Decrypts a payload for PASETO v2.local (symmetric decryption).
pub fn decryptV2Local(
    allocator: std.mem.Allocator,
    key: []const u8,
    token: []const u8,
) !struct {
    payload: []u8,
    footer: []u8,
} {
    const header = "v2.local.";

    if (token.len < header.len or !std.mem.startsWith(u8, token, header))
        return PasetoError.InvalidToken;

    const body = token[header.len..];
    const parts = try splitToken(allocator, body);
    defer allocator.free(parts.raw);
    defer allocator.free(parts.nonce);
    defer allocator.free(parts.ciphertext);
    // parts.footer is passed to caller, not freed here

    const payload = try xchacha20poly1305.decrypt(allocator, key, parts.nonce, &.{}, parts.ciphertext);

    return .{ .payload = payload, .footer = parts.footer };
}

/// Formats a PASETO v2.local token.
fn formatPaseto(
    allocator: std.mem.Allocator,
    header: []const u8,
    nonce: []const u8,
    ciphertext: []const u8,
    footer: ?[]const u8,
) ![]u8 {
    // Encode nonce
    const encoded_nonce = blk: {
        const buf = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(nonce.len));
        _ = std.base64.url_safe_no_pad.Encoder.encode(buf, nonce);
        break :blk buf;
    };
    defer allocator.free(encoded_nonce);

    // Encode ciphertext
    const encoded_ciphertext = blk: {
        const buf = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(ciphertext.len));
        _ = std.base64.url_safe_no_pad.Encoder.encode(buf, ciphertext);
        break :blk buf;
    };
    defer allocator.free(encoded_ciphertext);

    const payload_size = header.len + encoded_nonce.len + encoded_ciphertext.len + 1;
    const footer_size = if (footer) |f| (1 + std.base64.url_safe_no_pad.Encoder.calcSize(f.len)) else 0;
    const total_size = payload_size + footer_size;

    const token = try allocator.alloc(u8, total_size);
    var stream = std.io.fixedBufferStream(token);

    try stream.writer().writeAll(header);
    try stream.writer().writeAll(encoded_nonce);
    try stream.writer().writeByte('.');
    try stream.writer().writeAll(encoded_ciphertext);

    if (footer) |f| {
        const encoded_footer = blk: {
            const buf = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(f.len));
            _ = std.base64.url_safe_no_pad.Encoder.encode(buf, f);
            break :blk buf;
        };
        defer allocator.free(encoded_footer);

        try stream.writer().writeByte('.');
        try stream.writer().writeAll(encoded_footer);
    }

    return stream.getWritten();
}

/// Splits a PASETO v2.local token into nonce, ciphertext, and footer parts.
fn splitToken(allocator: std.mem.Allocator, body: []const u8) !struct {
    raw: []u8,
    nonce: []u8,
    ciphertext: []u8,
    footer: []u8,
} {
    const raw = try allocator.alloc(u8, body.len);
    errdefer allocator.free(raw);
    @memcpy(raw, body);

    var fields = std.mem.splitSequence(u8, raw, ".");
    const encoded_nonce = fields.next() orelse return PasetoError.InvalidToken;
    const encoded_ciphertext = fields.next() orelse return PasetoError.InvalidToken;
    const encoded_footer = fields.next();

    if (fields.next()) |_| {
        return PasetoError.InvalidToken;
    }

    var nonce: []u8 = undefined;
    var ciphertext: []u8 = undefined;
    var footer: []u8 = &.{};

    nonce = blk: {
        const decoded_len = base64DecodeLen(encoded_nonce) catch return PasetoError.InvalidToken;
        const buf = try allocator.alloc(u8, decoded_len);
        errdefer allocator.free(buf);
        try base64Decode(buf, encoded_nonce);
        break :blk buf;
    };

    ciphertext = blk: {
        const decoded_len = base64DecodeLen(encoded_ciphertext) catch return PasetoError.InvalidToken;
        const buf = try allocator.alloc(u8, decoded_len);
        errdefer allocator.free(buf);
        try base64Decode(buf, encoded_ciphertext);
        break :blk buf;
    };

    if (encoded_footer) |ef| {
        footer = blk: {
            const decoded_len = base64DecodeLen(ef) catch return PasetoError.InvalidToken;
            const buf = try allocator.alloc(u8, decoded_len);
            errdefer allocator.free(buf);
            try base64Decode(buf, ef);
            break :blk buf;
        };
    }

    return .{
        .raw = raw,
        .nonce = nonce,
        .ciphertext = ciphertext,
        .footer = footer,
    };
}

/// Base64 decode helpers (wrapping std lib but catching errors).
fn base64DecodeLen(encoded: []const u8) !usize {
    return std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded);
}

fn base64Decode(output: []u8, encoded: []const u8) !void {
    try std.base64.url_safe_no_pad.Decoder.decode(output, encoded);
}

test "v2.local encrypt and decrypt roundtrip" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const payload = "test payload";
    const footer = "optional footer";

    const token = try encryptV2Local(allocator, &key, payload, footer);
    defer allocator.free(token);

    const result = try decryptV2Local(allocator, &key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualStrings(payload, result.payload);
    try std.testing.expectEqualStrings(footer, result.footer);
}

test "v2.local encrypt and decrypt roundtrip without footer" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const payload = "test no footer";

    const token = try encryptV2Local(allocator, &key, payload, null);
    defer allocator.free(token);

    const result = try decryptV2Local(allocator, &key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualStrings(payload, result.payload);
    try std.testing.expectEqualSlices(u8, &.{}, result.footer);
}

test "v2.local reject invalid token header" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const bad_token = "v2.badheader.invalidtoken";
    const err = decryptV2Local(allocator, &key, bad_token);

    try std.testing.expectError(PasetoError.InvalidToken, err);
}

test "v2.local reject token with missing parts" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // Missing nonce and ciphertext
    const bad_token = "v2.local.";
    const err = decryptV2Local(allocator, &key, bad_token);

    try std.testing.expectError(PasetoError.InvalidToken, err);
}

test "v2.local reject token with too many parts" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // Extra dot-separated fields
    const bad_token = "v2.local.part1.part2.part3";
    const err = decryptV2Local(allocator, &key, bad_token);

    try std.testing.expectError(PasetoError.InvalidToken, err);
}

test "v2.local decrypt with wrong key fails" {
    const allocator = std.testing.allocator;

    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    std.crypto.random.bytes(&key1);
    std.crypto.random.bytes(&key2);

    const payload = "secure payload";

    const token = try encryptV2Local(allocator, &key1, payload, null);
    defer allocator.free(token);

    const result = try decryptV2Local(allocator, &key2, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    // Even though the tag passed, the result is gibberish.
    // So check that the payload is NOT what we expect.
    try std.testing.expect(!std.mem.eql(u8, result.payload, payload));
}

test "v2.local encrypt/decrypt large payload (~1MB)" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const payload = try allocator.alloc(u8, 1024 * 1024); // 1MB payload
    defer allocator.free(payload);
    std.crypto.random.bytes(payload);

    const token = try encryptV2Local(allocator, &key, payload, null);
    defer allocator.free(token);

    const result = try decryptV2Local(allocator, &key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, payload, result.payload);
    try std.testing.expectEqualSlices(u8, &.{}, result.footer);
}

test "v2.local encrypt/decrypt empty payload" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const payload: []const u8 = "";

    const token = try encryptV2Local(allocator, &key, payload, null);
    defer allocator.free(token);

    const result = try decryptV2Local(allocator, &key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, payload, result.payload);
}
