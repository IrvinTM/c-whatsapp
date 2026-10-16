/* wa_qr.h — terminal QR rendering for the pair-device flow.
 *
 * Baileys uses qrcode-terminal to draw a scannable QR in the terminal.
 * Here the pairing URL (https://wa.me/settings/linked_devices#...) built
 * in wa_socket.c emit_qr() is encoded with libqrencode and printed using
 * the same ANSIUTF8 half-block style as `qrencode -t ANSIUTF8`, so the
 * phone camera can scan it directly. Falls back to plain text when
 * libqrencode is unavailable.
 */
#ifndef WA_QR_H
#define WA_QR_H

#ifdef __cplusplus
extern "C" {
#endif

/* Render text as a scannable QR to stdout (with quiet zone). Always
 * safe to call; prints plain text if encoding fails. */
void wa_qr_print(const char *text);

#ifdef __cplusplus
}
#endif

#endif /* WA_QR_H */
