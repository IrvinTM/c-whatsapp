<img src="assets/icon.svg" width="64" height="64" alt="">

# c-whatsapp

C port of the [Baileys](https://github.com/WhiskeySockets/Baileys) WhatsApp
Linked-Device library (pinned to Baileys `74af8eee`, token table generated
via `tools/gen_tokens.py`).

## Status (v0.7.0)

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
- [x] Sending (`wa_send`): 1:1 text via X3DH + Double Ratchet, `usync`
      device discovery, per-device fanout, PN→LID conversion, device
      identity, ack wait, session reuse and persistence. Signed-prekey
      signatures are verified before X3DH.
- [x] Receiving: `pkmsg`/`msg` decryption, responder X3DH, out-of-order
      keys, session reload after restart, peer session resets, retry
      receipts, delivery receipts (and optional read receipts with
      `--read-receipts`).
- [x] Reminders: once/daily/weekly schedules, dates, fixed UTC-6 offset,
      CLI management, chat requests in a fixed format (`reminder every sat
      1pm class`, UTC-6) restricted to `CWA_ALLOW` numbers, `--daemon` and
      `--listen` modes. See [deploy/README.md](deploy/README.md) for
      running it as a small always-on service.

Still missing: group sender keys, media upload/download, rich message
types (replies, reactions, edits, polls, …), history/app-state sync,
contact/profile queries, presence/typing, prekey rotation/refill, and
stream resume. See the code comments and `include/wa_socket.h` for the
current API surface.

## Build & test

Requires `gcc`, `make`, OpenSSL + zlib + libsodium + qrencode dev headers:

```
# Arch:
sudo pacman -S --needed base-devel openssl zlib libsodium qrencode
# Debian/Ubuntu:
sudo apt-get install -y libssl-dev zlib1g-dev libsodium-dev libqrencode-dev
make        # builds build/c-whatsapp
make test   # codec, auth, noise, protobuf/pairing, signal, reminders
./build/c-whatsapp --help
```

`CMakeLists.txt` is provided as an alternative for environments with CMake.

### Live tests

Keep the other test phone out of git by putting it in the already-ignored
`test.env` at the repo root:

```
printf 'CWA_TEST_TO=15551234567\n' > test.env
chmod 600 test.env
tools/live-test.sh send "ping"
tools/live-test.sh listen
```

`tools/live-test.sh daemon` runs the reminder daemon with chat commands
allowed only for `CWA_ALLOW` (defaults to `CWA_TEST_TO`).

`auth_info/test.env` works the same way (it is ignored too). The helper
refuses to run until `CWA_TEST_TO` is set.
