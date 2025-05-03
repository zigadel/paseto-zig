const std = @import("std");
const paseto = @import("paseto-zig_lib").paseto;
const utils = @import("../utils.zig");

fn cmdGenerateKey(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !void {
    if (args.len < 1) {
        try stderr.print("Usage: generate-key <variant> [--json|--hex|--pem] [--out|--seed-out|--pub-out <file>]\n", .{});
        return error.InvalidArguments;
    }

    const variant = args[0];

    var emit_json = false;
    var emit_hex = false;
    var emit_pem = false;
    var out_path: ?[]const u8 = null;
    var seed_out_path: ?[]const u8 = null;
    var pub_out_path: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--json")) {
            emit_json = true;
        } else if (std.mem.eql(u8, args[i], "--hex")) {
            emit_hex = true;
        } else if (std.mem.eql(u8, args[i], "--pem")) {
            emit_pem = true;
        } else if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
            out_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--seed-out") and i + 1 < args.len) {
            seed_out_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--pub-out") and i + 1 < args.len) {
            pub_out_path = args[i + 1];
            i += 1;
        } else {
            try stderr.print("Unknown flag or missing value: {s}\n", .{args[i]});
            return error.InvalidArguments;
        }
    }

    if (std.mem.eql(u8, variant, "v2.local") or std.mem.eql(u8, variant, "v4.local")) {
        const key = try std.crypto.random.bytesAlloc(allocator, 32);
        defer allocator.free(key);

        const encoded = if (emit_hex)
            try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(key)})
        else
            try utils.encodeBase64Alloc(allocator, key);
        defer allocator.free(encoded);

        if (emit_json) {
            const json = try std.fmt.allocPrint(allocator, "{{ \"version\": \"{s}\", \"key\": \"{s}\" }}\n", .{ variant, encoded });
            defer allocator.free(json);
            if (out_path) |path| try utils.writeToFile(path, json) else try stdout.print("{s}", .{json});
        } else {
            if (out_path) |path| try utils.writeToFile(path, encoded) else try stdout.print("{s}\n", .{encoded});
        }
    } else if (std.mem.eql(u8, variant, "v2.public") or std.mem.eql(u8, variant, "v4.public")) {
        const seed = try std.crypto.random.bytesAlloc(allocator, 32);
        defer allocator.free(seed);
        const keypair = try paseto.crypto.ed25519.generateKeypairFromSeed(seed);

        const encoded_seed = if (emit_hex)
            try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(seed)})
        else
            try utils.encodeBase64Alloc(allocator, seed);
        defer allocator.free(encoded_seed);

        const encoded_pub = if (emit_hex)
            try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(keypair.public_key.toBytes())})
        else
            try utils.encodeBase64Alloc(allocator, keypair.public_key.toBytes());
        defer allocator.free(encoded_pub);

        if (emit_json) {
            const json = try std.fmt.allocPrint(
                allocator,
                "{{ \"version\": \"{s}\", \"seed\": \"{s}\", \"public_key\": \"{s}\" }}\n",
                .{ variant, encoded_seed, encoded_pub },
            );
            defer allocator.free(json);
            if (out_path) |path| try utils.writeToFile(path, json) else try stdout.print("{s}", .{json});
        } else {
            if (seed_out_path) |path| {
                try utils.writePemOrRaw(path, "PRIVATE KEY", seed, allocator, emit_pem);
            } else {
                try stdout.print("Seed: {s}\n", .{encoded_seed});
            }

            if (pub_out_path) |path| {
                try utils.writePemOrRaw(path, "PUBLIC KEY", keypair.public_key.toBytes(), allocator, emit_pem);
            } else {
                try stdout.print("Public: {s}\n", .{encoded_pub});
            }

            if (out_path) |path| {
                const combined = try std.fmt.allocPrint(allocator, "{s}\n{s}\n", .{ encoded_seed, encoded_pub });
                defer allocator.free(combined);
                try utils.writeToFile(path, combined);
            }
        }
    } else {
        try stderr.print("Unknown key variant: {s}\n", .{variant});
        return error.InvalidArguments;
    }
}
