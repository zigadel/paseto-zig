const std = @import("std");

pub const V4_LOCAL_HEADER = "v4.local.";
pub const V4_PUBLIC_HEADER = "v4.public.";

pub const XCHACHA20_KEY_SIZE = 32;
pub const XCHACHA20_NONCE_SIZE = 24;
pub const POLY1305_TAG_SIZE = 16;

pub const ED25519_PUBLIC_KEY_SIZE = 32;
pub const ED25519_SECRET_KEY_SIZE = 64;
pub const ED25519_SIGNATURE_SIZE = 64;

pub const FOOTER_MAX_SIZE = 512; // Reasonable limit for footer sizes (enforced optionally)

test "constants basic sanity" {
    try std.testing.expectEqualStrings(V4_LOCAL_HEADER, "v4.local.");
    try std.testing.expectEqual(XCHACHA20_KEY_SIZE, 32);
    try std.testing.expectEqual(ED25519_SIGNATURE_SIZE, 64);
}
