const std = @import("std");
const paseto = @import("paseto-zig_lib").paseto;

pub fn parseFlags(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    out_key: *?[]const u8,
    out_value: *?[]const u8,
    out_footer: *?[]const u8,
    err: anytype,
    value_name: []const u8,
) !void {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--key") and i + 1 < args.len) {
            out_key.* = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--key-file") and i + 1 < args.len) {
            out_key.* = try readFileAlloc(allocator, args[i + 1]);
            i += 1;
        } else if (std.mem.eql(u8, "--" ++ value_name, arg) and i + 1 < args.len) {
            out_value.* = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, "--" ++ value_name ++ "-file", arg) and i + 1 < args.len) {
            out_value.* = try readFileAlloc(allocator, args[i + 1]);
            i += 1;
        } else if (std.mem.eql(u8, "--footer", arg) and i + 1 < args.len) {
            out_footer.* = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, "--footer-file", arg) and i + 1 < args.len) {
            out_footer.* = try readFileAlloc(allocator, args[i + 1]);
            i += 1;
        } else {
            try err.print("Invalid flag or missing value: {s}\n", .{arg});
            return error.InvalidArguments;
        }
    }

    if (out_key.* == null or out_value.* == null) {
        if (out_value.* == null)
            out_value.* = try readStdinAlloc(allocator);

        if (out_key.* == null) {
            try err.print("Missing --key or --key-file\n", .{});
            return error.InvalidArguments;
        }
    }
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    const buf = try allocator.alloc(u8, stat.size);
    _ = try file.readAll(buf);
    return buf;
}

fn readStdinAlloc(allocator: std.mem.Allocator) ![]const u8 {
    const stdin = std.io.getStdIn();
    var reader = stdin.reader();
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    var temp: [1024]u8 = undefined;
    while (true) {
        const n = try reader.read(&temp);
        if (n == 0) break;
        try buf.appendSlice(temp[0..n]);
    }
    return buf.toOwnedSlice();
}

fn encodeBase64Alloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const len = std.base64.url_safe_no_pad.Encoder.calcSize(input.len);
    const buf = try allocator.alloc(u8, len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(buf, input);
    return buf;
}

fn encodeBase58Alloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    var x = std.bigint.Mutable.init(allocator);
    defer x.deinit();
    try x.setBytes(input);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();

    while (!x.isZero()) {
        const rem = try x.divRemSmall(58);
        try out.append(base58_alphabet[rem]);
    }

    // Add leading zeros (0x00) as '1's in base58
    for (input) |b| {
        if (b == 0x00)
            try out.append('1')
        else
            break;
    }

    const result = out.items;
    std.mem.reverse(u8, result);
    return allocator.dupe(u8, result);
}

pub fn decodeKey(allocator: std.mem.Allocator, input: []const u8, expected_len: usize) ![]const u8 {
    if (input.len == expected_len) return input;

    const hex_buf = try allocator.alloc(u8, expected_len);
    errdefer allocator.free(hex_buf);
    if (std.fmt.hexToBytes(hex_buf, input)) |_| {
        return hex_buf;
    } else |_| {
        // fall through to base64 decoding
    }

    const b64_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(input) catch return error.InvalidKey;
    const b64_buf = try allocator.alloc(u8, b64_len);
    errdefer allocator.free(b64_buf);

    std.base64.url_safe_no_pad.Decoder.decode(b64_buf, input) catch return error.InvalidKey;
    if (b64_buf.len != expected_len) return error.InvalidKey;
    return b64_buf;
}

pub fn printOutput(msg: []const u8, use_json: bool, use_color: bool) !void {
    const out = std.io.getStdOut().writer();
    if (use_json) {
        try out.print("{{ \"output\": \"{s}\" }}\n", .{msg});
    } else if (use_color) {
        try out.print("\x1b[32m{s}\x1b[0m\n", .{msg});
    } else {
        try out.print("{s}\n", .{msg});
    }
}

pub fn printError(err_msg: []const u8, use_json: bool, use_color: bool) !void {
    const out = std.io.getStdErr().writer();
    if (use_json) {
        try out.print("{{ \"error\": \"{s}\" }}\n", .{err_msg});
    } else if (use_color) {
        try out.print("\x1b[31mError: {s}\x1b[0m\n", .{err_msg});
    } else {
        try out.print("Error: {s}\n", .{err_msg});
    }
}

pub fn printUsage(use_color: bool, usage: []const u8) !void {
    const out = std.io.getStdErr().writer();
    if (use_color) try out.print("\x1b[34m", .{});
    try out.print("{s}", .{usage});
    if (use_color) try out.print("\x1b[0m", .{});
    return error.InvalidArguments;
}

fn writeToFile(path: []const u8, content: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    _ = try file.writeAll(content);
}

fn encodePEM(label: []const u8, data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const b64 = try encodeBase64Alloc(allocator, data);
    defer allocator.free(b64);

    var buf = std.ArrayList(u8).init(allocator);
    const writer = buf.writer();
    try writer.print("-----BEGIN {s}-----\n", .{label});

    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        const line = b64[i..@min(i + 64, b64.len)];
        try writer.print("{s}\n", .{line});
    }

    try writer.print("-----END {s}-----\n", .{label});
    return buf.toOwnedSlice();
}

fn writePemOrRaw(path: []const u8, label: []const u8, bytes: []const u8, allocator: std.mem.Allocator, as_pem: bool) !void {
    const content = if (as_pem) try encodePEM(label, bytes, allocator) else bytes;
    defer if (as_pem) allocator.free(content);
    try writeToFile(path, content);
}
