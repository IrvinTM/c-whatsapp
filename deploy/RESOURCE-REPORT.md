# c-whatsapp daemon resource report

Measured 2026-10-30 on this machine (x86_64, Ubuntu, OpenSSL 3) with the
`make tiny` build running as a systemd user service:
`c-whatsapp --daemon --read-receipts --timeout 0`, one linked account, one
allowed chat number, after login, one reminder sent, then idle.

## Summary

| Resource | Value |
|---|---|
| Binary size (stripped, `-Os`, LTO) | **170 KB** (debug build: 415 KB) |
| Memory charged by systemd (cgroup) | **3.7 MB** current, **4.2 MB** peak |
| Private memory (Private_Dirty + Private_Clean) | **4.7 MB** (3.6 MB dirty heap/stack) |
| RSS (includes shared libc/OpenSSL pages) | 11.7 MB |
| PSS (fair share of shared pages) | 6.1 MB |
| Swap | 0 |
| Threads / processes | 1 / 1 |
| Open file descriptors | 4 (stdin, stdout/stderr journal, 1 TLS socket) |
| CPU: login + prekey upload + 1 send | ~23 ms total |
| CPU: idle | ~2.9 ms per 2 min ≈ **0.002 %** of one core (~2 s/day) |
| Network: idle | ~0.8 KB per 2 min of payload ≈ **0.6 MB/day** (~1 MB/day with TCP/IP headers) |
| Network: login + one reminder | ~12 KB |
| Disk state (`auth_info/`) | ~6 KB (bounded: ≤64 prekeys, ≤128 sessions) |
| Inbound ports | none (one outbound TLS connection to WhatsApp) |

## Where the memory goes

- **VmLib 7.2 MB** is shared, read-only library code (libcrypto alone is
  6.4 MB on disk). It counts in RSS, but it's shared with every other
  OpenSSL user and the kernel can drop it under memory pressure. This is why
  RSS (11.7 MB) is so much bigger than what the service is charged (3.7 MB).
- **Private dirty ~3.6 MB** covers OpenSSL's initialized state, the heap, and
  the Signal session store. The store is a 1 MB block (`wa_sig_t`: 128
  sessions × 7.8 KB + 64 prekeys). Only touched pages count.
- **VmExe 88 KB**: the program's own code.

## Guardrails in the unit

`MemoryMax=64M`, `TasksMax=16`, `Nice=10`, `Restart=always`. Peak use was
about 7 % of the memory cap.

## Fits on

Any VM with 128 MB of RAM or more. On a 512 MB / 1 vCPU instance the daemon is
noise. It needs `libssl3`, `zlib`, `libsodium` and `libqrencode` installed;
these are shared and mostly already present.

## Possible further reductions (not done)

- Static link against a small TLS stack (e.g. BearSSL/mbedTLS) instead of
  OpenSSL: RSS would drop to ~2–3 MB, but that's a large porting job.
- Drop `libqrencode` from the daemon build (it's only used for QR linking):
  saves ~55 KB of shared library.
- Allocate Signal sessions on demand instead of the fixed 1 MB array:
  saves ≤1 MB only once many contacts exist.
