const std = @import("std");
const paseto = @import("paseto-zig_lib").paseto;
const utils = @import("../utils.zig");

pub fn cmdV2LocalEncrypt(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stderr: anytype,
    use_json: bool,
    use_color: bool,
) !void {
    var key: ?[]const u8 = null;
    var message: ?[]const u8 = null;
    var footer: ?[]const u8 = null;
    try utils.parseFlags(allocator, args, &key, &message, &footer, stderr, "message");

    const key_bytes = try utils.decodeKey(allocator, key.?, 32);
    const token = try paseto.v2.local.encryptV2Local(allocator, key_bytes, message.?, footer);
    defer allocator.free(token);
    try utils.printOutput(token, use_json, use_color);
}

pub fn cmdV2LocalDecrypt(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stderr: anytype,
    use_json: bool,
    use_color: bool,
) !void {
    var key: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var footer: ?[]const u8 = null;
    try utils.parseFlags(allocator, args, &key, &token, &footer, stderr, "token");

    const key_bytes = try utils.decodeKey(allocator, key.?, 32);
    const result = try paseto.v2.local.decryptV2Local(allocator, key_bytes, token.?);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try utils.printOutput(result.payload, use_json, use_color);
}

pub fn cmdV2PublicSign(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stderr: anytype,
    use_json: bool,
    use_color: bool,
) !void {
    var sk: ?[]const u8 = null;
    var msg: ?[]const u8 = null;
    var footer: ?[]const u8 = null;
    try utils.parseFlags(allocator, args, &sk, &msg, &footer, stderr, "message");

    const keypair = try paseto.crypto.ed25519.generateKeypairFromSeed(
        try utils.decodeKey(allocator, sk.?, 32),
    );
    const token = try paseto.v2.public.signV2Public(allocator, keypair, msg.?, footer);
    defer allocator.free(token);
    try utils.printOutput(token, use_json, use_color);
}

pub fn cmdV2PublicVerify(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stderr: anytype,
    use_json: bool,
    use_color: bool,
) !void {
    var pk: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var footer: ?[]const u8 = null;
    try utils.parseFlags(allocator, args, &pk, &token, &footer, stderr, "token");

    const pubkey = try utils.decodeKey(allocator, pk.?, 32);
    const result = try paseto.v2.public.verifyV2Public(allocator, pubkey.*, token.?);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try utils.printOutput(result.payload, use_json, use_color);
}

test "v2 local encrypt + decrypt roundtrip (direct Paseto call)" {
    const allocator = std.testing.allocator;

    const key_b64 = "LkzY4vM2ELmLB97KiKwU6AMOQkPQFLgFdEKz8nNV2Cw=";
    const key = try utils.decodeKey(allocator, key_b64, 32);
    defer allocator.free(key);

    const message = "hello unit test";
    const token = try paseto.v2.local.encryptV2Local(allocator, key, message, null);
    defer allocator.free(token);

    const result = try paseto.v2.local.decryptV2Local(allocator, key, token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualStrings(message, result.payload);
}
