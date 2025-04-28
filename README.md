# paseto-zig

Modern, secure PASETO (Platform-Agnostic Security Tokens) library in pure Zig.

# ✨ Overview

paseto-zig is a production-quality implementation of PASETO v4.local encryption, based on:

- XChaCha20-Poly1305 authenticated encryption (high-security AEAD)

- Constant-time tag comparison to resist timing attacks

- Detached mode (optional): supports separated ciphertext and tag handling

- Robust error handling with precise error types

- Memory safety: no leaks, secure zeroization of sensitive keys

- Fully tested against edge cases, tampering, invalid inputs, large inputs, etc.

Written entirely in pure Zig, no external dependencies.

# 🚀 Features

- 🔒 Secure by default (state-of-the-art primitives)

- ⚡ Fast and low-overhead

- 🔬 Extensive unit tests (including tampering, wrong AAD, truncated ciphertext, etc.)

- 🧹 Automatic memory management (errdefer, allocator-safe, zeroize keys)

- 🧠 Simple API for encryption and decryption

# 📦 Usage

**Encrypt**:

```
const paseto = @import("path/to/paseto-zig/src/lib/crypto/xchacha20poly1305.zig");

const ciphertext = try paseto.encrypt(
    allocator,
    key,        // 32 bytes
    nonce,      // 24 bytes
    aad,        // Additional Authenticated Data
    plaintext   // Message to encrypt
);
```

**Decrypt**:

```
const plaintext = try paseto.decrypt(
    allocator,
    key,        // 32 bytes
    nonce,      // 24 bytes
    aad,        // Must match during decryption
    ciphertext  // Ciphertext + Poly1305 tag
);
```

# 📚 PASETO v4.local Overview

- v4.local = symmetric authenticated encryption

- Powered by XChaCha20 (stream cipher) + Poly1305 (MAC)

- Safer and easier than JWT: no algorithm confusion attacks, no RS256 vs HS256 mistakes

# 🔧 Build & Test

```sh
zig build test
```

You should see:

```css
All tests passed!
```

Tests cover:

- Successful encrypt/decrypt roundtrips

- Tampering detection

- Wrong AAD rejection

- Truncated ciphertext handling

- Empty plaintext handling

- Large (1MB+) payloads

- Invalid key/nonce size errors

# 📜 MIT License

# 🛠️ Roadmap (Optional Future)

- [x] Full PASETO v4.public support (Ed25519 signatures)

- [ ] PASETO v2.local (legacy AES-GCM-SIV mode)

- [ ] Optimized streaming encryption for very large payloads

- [ ] CLI tool for token generation/verification

- [ ] WASM compilation support (for web usage)

# 🤝 Contributions

PRs welcome!

Let's build industry standard Zig crypto tools together. 🚀