const std = @import("std");
const paseto = @import("paseto-zig_lib").paseto;
const utils = @import("utils.zig");
const v2 = @import("cmds/v2.zig");
const v4 = @import("cmds/v4.zig");
const fingerprint = @import("cmds/fingerprint.zig");
const generate_key = @import("cmds/generate_key.zig");
const inspect = @import("cmds/inspect.zig");
const repl = @import("cmds/repl.zig");

const VERSION = "0.1.0";
var use_color = false;
var use_json = false;

const USAGE =
    \\Usage:
    \\  paseto-zig <command> [options]
    \\
    \\Commands:
    \\  v2-local-encrypt   --key <key> --message <msg> [--footer <f>]
    \\  v2-local-decrypt   --key <key> --token <token>
    \\  v2-public-sign     --key <sk>  --message <msg> [--footer <f>]
    \\  v2-public-verify   --key <pk>  --token <token>
    \\
    \\  v4-local-encrypt   --key <key> --message <msg> [--footer <f>]
    \\  v4-local-decrypt   --key <key> --token <token>
    \\  v4-public-sign     --key <sk>  --message <msg> [--footer <f>]
    \\  v4-public-verify   --key <pk>  --token <token>
    \\
    \\  generate-key v2.local | v2.public | v4.local | v4.public
    \\    Options: [--json] [--hex] [--pem] [--out <file>] [--seed-out <file>] [--pub-out <file>]
    \\
    \\  fingerprint --key <key> [--hex|--base58]
    \\  fingerprint --key-file <path> [--hex|--base58]
    \\
    \\Options:
    \\  --*-file inputs supported for key, message, token, and footer
    \\  If --message or --token is omitted, stdin will be used
    \\  Keys can be raw, hex, or base64url
    \\  --version       Print version
    \\  --help          Show help
;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return utils.printUsage();

    var cmd_index: usize = 1;
    var i: usize = 1;
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

    if (cmd_index >= args.len) return utils.printUsage();

    const cmd = args[cmd_index];
    const sub_args = args[(cmd_index + 1)..];

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try stdout.print("{s}\n", .{USAGE});
        return;
    } else if (std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-v")) {
        try stdout.print("paseto-zig version {s}\n", .{VERSION});
        return;
    } else if (std.mem.eql(u8, cmd, "repl")) {
        return try repl.startRepl(allocator, VERSION, USAGE);
    } else if (std.mem.eql(u8, cmd, "inspect-token")) {
        try inspect.cmdInspectToken(sub_args, stdout);
    } else if (std.mem.eql(u8, cmd, "fingerprint")) {
        try fingerprint.cmdFingerprint(allocator, sub_args, stdout, stderr);
    } else if (std.mem.eql(u8, cmd, "generate-key")) {
        try generate_key.cmdGenerateKey(allocator, sub_args, stdout, stderr);
    } else if (std.mem.eql(u8, cmd, "v2-local-encrypt")) {
        try v2.cmdV2LocalEncrypt(allocator, sub_args, stderr, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v2-local-decrypt")) {
        try v2.cmdV2LocalDecrypt(allocator, sub_args, stderr, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v2-public-sign")) {
        try v2.cmdV2PublicSign(allocator, sub_args, stderr, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v2-public-verify")) {
        try v2.cmdV2PublicVerify(allocator, sub_args, stderr, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v4-local-encrypt")) {
        try v4.cmdV4LocalEncrypt(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v4-local-decrypt")) {
        try v4.cmdV4LocalDecrypt(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v4-public-sign")) {
        try v4.cmdV4PublicSign(allocator, sub_args, stderr, use_json, use_color);
    } else if (std.mem.eql(u8, cmd, "v4-public-verify")) {
        try v4.cmdV4PublicVerify(allocator, sub_args, stderr, use_json, use_color);
    } else {
        return utils.printUsage();
    }
}
