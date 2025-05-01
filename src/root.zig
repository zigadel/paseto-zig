const std = @import("std");

pub const paseto = @import("lib/paseto.zig");

test {
    std.testing.refAllDeclsRecursive(@This());
}
