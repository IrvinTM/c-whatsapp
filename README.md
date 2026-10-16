<img src="assets/icon.svg" width="64" height="64" alt="">

# c-whatsapp

C port of the [Baileys](https://github.com/WhiskeySockets/Baileys) WhatsApp
Linked-Device library (pinned to Baileys `74af8eee`, token table generated
via `tools/gen_tokens.py`).

## Status (v0.1 skeleton)

- [x] `wa_auth` — file-backed session store (`auth_info/creds.json`),
      like `useMultiFileAuthState`
- [x] `wa_noise` — Noise XX handshake (OpenSSL: X25519, AES-256-GCM,
      HKDF-SHA256, XEdDSA verify), transport state, frame encode/feed,
      zlib-compressed nodes. Cross-checked byte-for-byte against Baileys
      handshake math via `node:crypto`
- [x] `wa_pb` + `wa_ws` + `wa_socket` — hand-rolled protobuf
      (Handshake/ClientPayload/CertChain), minimal WSS client (TLS+WS),
      full handshake against the real server, QR `pair-device` flow.
      Verified live: `./build/c-whatsapp --qr` prints a scannable QR.
- [x] Pair-success (`wa_pairing`): ADV HMAC/account-signature verify,
      XEdDSA device signature (libsodium), reply stanza, creds update.
      Post-login: one-time prekey upload + presence announce queries.
- [x] Pairing-code linking (`--pair NUMBER`): PBKDF2 + AES-CTR wrapped
      ephemeral key, `link_code_companion_reg` stanza — no camera needed.
- [ ] `wa_send` — Signal session establishment (X3DH/Double Ratchet) +
      message encrypt/relay (Phase 5b)

## Build & test

Requires `gcc`, `make`, OpenSSL + zlib + libsodium + qrencode dev headers:

```
# Arch:
sudo pacman -S --needed base-devel openssl zlib libsodium qrencode
# Debian/Ubuntu:
sudo apt-get install -y libssl-dev zlib1g-dev libsodium-dev libqrencode-dev
make        # builds build/c-whatsapp
make test   # binary codec + auth store + noise + protobuf/pairing
./build/c-whatsapp --help
```

`CMakeLists.txt` is provided as an alternative for environments with CMake.
