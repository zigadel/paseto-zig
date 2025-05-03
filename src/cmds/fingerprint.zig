const std = @import("std");
const paseto = @import("paseto-zig_lib").paseto;
const utils = @import("../utils.zig");

fn cmdFingerprint(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !void {
    var input: ?[]const u8 = null;
    var input_file: ?[]const u8 = null;
    var use_hex = false;
    var use_base58 = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--key") and i + 1 < args.len) {
            input = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--key-file") and i + 1 < args.len) {
            input_file = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--hex")) {
            use_hex = true;
        } else if (std.mem.eql(u8, arg, "--base58")) {
            use_base58 = true;
        } else {
            try stderr.print("Unknown flag or missing value: {s}\n", .{arg});
            return error.InvalidArguments;
        }
    }

    if (input == null and input_file == null) {
        try stderr.print("Missing --key or --key-file\n", .{});
        return error.InvalidArguments;
    }

    const raw = if (input_file) |path|
        try utils.readFileAlloc(allocator, path)
    else
        input.?;

    // Decode key from base64 or hex if needed
    const key_bytes = try utils.decodeKey(allocator, raw, 32);
    defer allocator.free(key_bytes);

    // Hash with SHA-256 (or BLAKE3 if preferred)
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_bytes, &hash);

    if (use_base58) {
        const base58 = try utils.encodeBase58Alloc(allocator, &hash);
        defer allocator.free(base58);
        try stdout.print("Fingerprint (base58): {s}\n", .{base58});
    } else {
        try stdout.print("Fingerprint (hex): {s}\n", .{std.fmt.fmtSliceHexLower(&hash)});
    }
}
