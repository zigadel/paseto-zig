const std = @import("std");

pub const PasetoError = error{
    InvalidToken,
    InvalidFooter,
    CryptoFailure,
    DecodeError,
    SignatureMismatch,
    InvalidKey,
    InvalidNonce,
    InvariantViolation,
};

test "PasetoError basic match" {
    const err: PasetoError = PasetoError.InvalidToken;

    switch (err) {
        PasetoError.InvalidToken => {
            // Pass: Correct error detected
        },
        else => {
            std.debug.panic("Unexpected error type");
        },
    }
}
