const std = @import("std");
const v2 = @import("v2.zig");
const v4 = @import("v4.zig");
const generate_key = @import("generate_key.zig");
const inspect = @import("inspect.zig");
const fingerprint = @import("fingerprint.zig");
const utils = @import("../utils.zig");

pub fn startRepl(
    allocator: std.mem.Allocator,
    version: []const u8,
    usage: []const u8,
) !void {
    const stdin = std.io.getStdIn().reader();
    const stdout = std.io.getStdOut().writer();

    try stdout.print("paseto-zig REPL v{s}\nType `exit` or `quit` to leave.\n\n", .{version});

    var line_buf = std.ArrayList(u8).init(allocator);
    defer line_buf.deinit();

    while (true) {
        try stdout.print("> ", .{});
        try stdout.flush();
        line_buf.clearRetainingCapacity();

        const line = try stdin.readUntilDelimiterAlloc(allocator, '\n', 4096);
        defer allocator.free(line);

        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (std.mem.eql(u8, trimmed, "exit") or std.mem.eql(u8, trimmed, "quit")) break;

        var tokens = std.ArrayList([]const u8).init(allocator);
        defer tokens.deinit();

        var it = std.mem.tokenizeScalar(u8, trimmed, ' ');
        while (it.next()) |tok| try tokens.append(tok);

        if (tokens.items.len == 0) continue;

        var argv = try allocator.alloc([]const u8, tokens.items.len + 1);
        defer allocator.free(argv);
        argv[0] = "repl";
        std.mem.copy([]const u8, argv[1..], tokens.items);

        const result = try runCommand(allocator, argv, version, usage);
        if (result) |err| try stdout.print("Error: {s}\n", .{@errorName(err)});
    }
}

fn runCommand(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    version: []const u8,
    usage: []const u8,
) !?anyerror {
    if (args.len < 2) return utils.printUsage(true, usage);

    var cmd_index: usize = 1;
    var i: usize = 1;
    var use_color = false;
    var use_json = false;

    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--color")) {
            use_color = true;
        } else if (std.mem.eql(u8, args[i], "--json")) {
            use_json = true;
        } else {
            cmd_index = i;
            break;
        }
    }

    if (cmd_index >= args.len) return utils.printUsage(true, usage);

    const cmd = args[cmd_index];
    const sub_args = args[(cmd_index + 1)..];
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try stdout.print("{s}\n", .{usage});
        return null;
    } else if (std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-v")) {
        try stdout.print("paseto-zig version {s}\n", .{version});
        return null;
    } else if (std.mem.eql(u8, cmd, "fingerprint")) {
        try fingerprint.cmdFingerprint(allocator, sub_args, stdout, stderr);
    } else if (std.mem.eql(u8, cmd, "inspect-token")) {
        try inspect.cmdInspectToken(sub_args, stdout, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "generate-key")) {
        try generate_key.cmdGenerateKey(allocator, sub_args, stdout, stderr, use_json);
    } else if (std.mem.eql(u8, cmd, "v2-local-encrypt")) {
        try v2.cmdV2LocalEncrypt(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v2-local-decrypt")) {
        try v2.cmdV2LocalDecrypt(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v2-public-sign")) {
        try v2.cmdV2PublicSign(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v2-public-verify")) {
        try v2.cmdV2PublicVerify(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v4-local-encrypt")) {
        try v4.cmdV4LocalEncrypt(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v4-local-decrypt")) {
        try v4.cmdV4LocalDecrypt(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v4-public-sign")) {
        try v4.cmdV4PublicSign(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v4-public-verify")) {
        try v4.cmdV4PublicVerify(allocator, sub_args, stderr, use_json, use_color);
    } else {
        return utils.printUsage(use_color, usage);
    }

    return null;
}
