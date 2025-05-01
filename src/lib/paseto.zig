pub const v2 = struct {
    pub const local = @import("v2/local.zig");
    pub const public = @import("v2/public.zig");
};

pub const v4 = struct {
    pub const local = @import("v4/local.zig");
    pub const public = @import("v4/public.zig");
};

pub const crypto = struct {
    pub const ed25519 = @import("crypto/ed25519.zig");
    pub const xchacha20poly1305 = @import("crypto/xchacha20poly1305.zig");
};

pub const PasetoError = @import("errors.zig").PasetoError;
