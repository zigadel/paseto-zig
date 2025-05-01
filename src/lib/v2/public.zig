const std = @import("std");
const ed25519 = @import("../crypto/ed25519.zig");
const PasetoError = @import("../errors.zig").PasetoError;

const Encoder = std.base64.url_safe_no_pad.Encoder;
const Decoder = std.base64.url_safe_no_pad.Decoder;

pub const PublicToken = struct {
    keypair: ed25519.KeyPair,

    pub fn init(keypair: ed25519.KeyPair) PublicToken {
        return .{ .keypair = keypair };
    }

    pub fn sign(
        self: PublicToken,
        allocator: std.mem.Allocator,
        payload: []const u8,
        footer: ?[]const u8,
    ) ![]u8 {
        const signature = try ed25519.sign(self.keypair, payload);

        // Base64-encode payload
        const payload_b64_len = Encoder.calcSize(payload.len);
        const payload_b64 = try allocator.alloc(u8, payload_b64_len);
        defer allocator.free(payload_b64);
        _ = Encoder.encode(payload_b64, payload);

        // Base64-encode signature
        const sig_b64_len = Encoder.calcSize(signature.len);
        const sig_b64 = try allocator.alloc(u8, sig_b64_len);
        defer allocator.free(sig_b64);
        _ = Encoder.encode(sig_b64, &signature);

        var token = try std.mem.concat(allocator, u8, &[_][]const u8{
            "v2.public.", payload_b64, ".", sig_b64,
        });

        if (footer) |f| {
            const footer_b64_len = Encoder.calcSize(f.len);
            const footer_b64 = try allocator.alloc(u8, footer_b64_len);
            defer allocator.free(footer_b64);
            _ = Encoder.encode(footer_b64, f);

            const with_footer = try std.mem.concat(allocator, u8, &[_][]const u8{
                token, ".", footer_b64,
            });
            allocator.free(token);
            token = with_footer;
        }

        return token;
    }

    pub fn verify(
        allocator: std.mem.Allocator,
        public_key: [ed25519.ED25519_PUBLIC_KEY_SIZE]u8,
        token: []const u8,
    ) !struct { payload: []u8, footer: []u8 } {
        if (!std.mem.startsWith(u8, token, "v2.public.")) {
            return PasetoError.InvalidToken;
        }

        const token_body = token["v2.public.".len..];
        var parts = std.mem.splitSequence(u8, token_body, ".");
        const base_payload = parts.next() orelse return PasetoError.InvalidToken;
        const base_sig = parts.next() orelse return PasetoError.InvalidToken;

        const payload = try decodeBase64Alloc(allocator, base_payload);
        errdefer allocator.free(payload);

        const signature = try decodeBase64Alloc(allocator, base_sig);
        defer allocator.free(signature);

        try ed25519.verify(public_key, payload, signature);

        var footer: []u8 = &.{};
        if (parts.next()) |footer_b64| {
            footer = try decodeBase64Alloc(allocator, footer_b64);
        }

        return .{ .payload = payload, .footer = footer };
    }
};

fn decodeBase64Alloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const output_len = try Decoder.calcSizeForSlice(input);
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);
    _ = try Decoder.decode(output, input);
    return output;
}

// ---------------------------
//           TESTS
// ---------------------------

test "v2.public token roundtrip with footer" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();
    const paseto = PublicToken.init(keypair);

    const message = "hello world";
    const footer = "footer-check";

    const token = try paseto.sign(allocator, message, footer);
    defer allocator.free(token);

    const result = try PublicToken.verify(allocator, keypair.public_key.toBytes(), token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, result.payload, message);
    try std.testing.expectEqualSlices(u8, result.footer, footer);
}

test "v2.public token roundtrip without footer" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();
    const paseto = PublicToken.init(keypair);

    const message = "no-footer";

    const token = try paseto.sign(allocator, message, null);
    defer allocator.free(token);

    const result = try PublicToken.verify(allocator, keypair.public_key.toBytes(), token);
    defer allocator.free(result.payload);
    defer allocator.free(result.footer);

    try std.testing.expectEqualSlices(u8, result.payload, message);
    try std.testing.expectEqual(result.footer.len, 0);
}

test "v2.public token fails if tampered" {
    const allocator = std.testing.allocator;
    const keypair = ed25519.generateKeypair();
    const paseto = PublicToken.init(keypair);

    const token = try paseto.sign(allocator, "payload", null);
    defer allocator.free(token);

    var tampered = try allocator.dupe(u8, token);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    const result = PublicToken.verify(allocator, keypair.public_key.toBytes(), tampered);

    const expected_errors = [_]anyerror{
        PasetoError.CryptoFailure,
        error.InvalidEncoding,
        error.InvalidPadding,
        error.InvalidCharacter,
        error.SignatureVerificationFailed,
    };
    var matched = false;
    for (expected_errors) |err| {
        if (result == err) {
            matched = true;
            break;
        }
    }
    try std.testing.expect(matched);
}

test "v2.public token fails with wrong key" {
    const allocator = std.testing.allocator;
    const keypair1 = ed25519.generateKeypair();
    const keypair2 = ed25519.generateKeypair();
    const paseto = PublicToken.init(keypair1);

    const token = try paseto.sign(allocator, "payload", null);
    defer allocator.free(token);

    const result = PublicToken.verify(allocator, keypair2.public_key.toBytes(), token);

    const expected_errors = [_]anyerror{
        PasetoError.CryptoFailure,
        error.SignatureVerificationFailed,
    };
    var matched = false;
    for (expected_errors) |err| {
        if (result == err) {
            matched = true;
            break;
        }
    }
    try std.testing.expect(matched);
}
