const std = @import("std");
const paseto = @import("paseto-zig_lib").paseto;
const utils = @import("../utils.zig");

pub fn cmdV4LocalEncrypt(
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
    const token = try paseto.v4.local.encryptV4Local(allocator, key_bytes, message.?, footer);
    defer allocator.free(token);

    try utils.printOutput(token, use_json, use_color);
}

pub fn cmdV4LocalDecrypt(
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
    const result = try paseto.v4.local.decryptV4Local(allocator, key_bytes, token.?);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try utils.printOutput(result.payload, use_json, use_color);
}

pub fn cmdV4PublicSign(
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
    const token = try paseto.v4.public.signV4Public(allocator, keypair, msg.?, footer);
    defer allocator.free(token);

    try utils.printOutput(token, use_json, use_color);
}

pub fn cmdV4PublicVerify(
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
    const result = try paseto.v4.public.verifyV4Public(allocator, pubkey.*, token.?);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try utils.printOutput(result.payload, use_json, use_color);
}
