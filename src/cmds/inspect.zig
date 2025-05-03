const std = @import("std");
const paseto = @import("paseto-zig_lib").paseto;
const utils = @import("../utils.zig");

fn cmdInspectToken(
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
    use_json: bool,
    use_color: bool,
) !void {
    if (args.len < 1) {
        try stderr.print("Usage: inspect-token <token>\n", .{});
        return error.InvalidArguments;
    }

    const token = args[0];
    var parts = std.mem.tokenizeScalar(u8, token, '.');

    const version = parts.next() orelse {
        try stderr.print("Invalid token: missing version\n", .{});
        return error.InvalidArguments;
    };

    const purpose = parts.next() orelse {
        try stderr.print("Invalid token: missing purpose\n", .{});
        return error.InvalidArguments;
    };

    if (use_json) {
        try stdout.print(
            "{{ \"version\": \"v{s}\", \"purpose\": \"{s}\" }}\n",
            .{ version[1], purpose },
        );
    } else if (use_color) {
        try stdout.print("\x1b[36mVersion:\x1b[0m v{s}\n\x1b[36mPurpose:\x1b[0m {s}\n", .{ version[1], purpose });
    } else {
        try stdout.print("Version: v{s}\nPurpose: {s}\n", .{ version[1], purpose });
    }
}
