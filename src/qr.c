/* wa_qr.c — terminal QR rendering (see wa_qr.h). */
#include "wa_qr.h"

#include <stdio.h>

#if defined(__has_include)
#if __has_include(<qrencode.h>)
#define WA_HAVE_QRENCODE 1
#endif
#elif defined(__linux__)
/* Assume system libqrencode when the header check is unavailable. */
#define WA_HAVE_QRENCODE 1
#endif

#ifdef WA_HAVE_QRENCODE
#include <qrencode.h>

/* libqrencode: data[y*width+x] & 1 == black module. Margin modules are white.
 * Output matches `qrencode -t ANSIUTF8`: black background + white foreground,
 * one terminal cell = two vertical modules via half-blocks:
 *   white/white -> FULL BLOCK, white/black -> UPPER HALF,
 *   black/white -> LOWER HALF, black/black -> space. */
void wa_qr_print(const char *text) {
    QRcode *q;
    const int margin = 4; /* spec quiet zone */
    int w, h, x, y;

    if (!text || !*text)
        return;
    q = QRcode_encodeString(text, 0, QR_ECLEVEL_M, QR_MODE_8, 1);
    if (!q) {
        /* Encoding failed (text too long?): fall back to plain URL. */
        printf("%s\n", text);
        fflush(stdout);
        return;
    }
    w = q->width;
    h = q->width;
    for (y = -margin; y < h + margin; y += 2) {
        printf("\033[40;37;1m");
        for (x = -margin; x < w + margin; x++) {
            int top = 0, bottom = 0;
            if (x >= 0 && x < w && y >= 0 && y < h)
                top = (q->data[y * w + x] & 1) ? 1 : 0;
            if (x >= 0 && x < w && y + 1 >= 0 && y + 1 < h)
                bottom = (q->data[(y + 1) * w + x] & 1) ? 1 : 0;
            if (!top && !bottom)
                printf("\342\226\210"); /* U+2588 FULL BLOCK (white) */
            else if (!top && bottom)
                printf("\342\226\200"); /* U+2580 UPPER HALF (white top) */
            else if (top && !bottom)
                printf("\342\226\204"); /* U+2584 LOWER HALF (white bottom) */
            else
                printf(" ");
        }
        printf("\033[0m\n");
    }
    QRcode_free(q);
    fflush(stdout);
}
#else
/* No libqrencode: plain-text fallback so the URL stays copy-pasteable. */
void wa_qr_print(const char *text) {
    if (!text)
        return;
    printf("%s\n", text);
    fflush(stdout);
}
#endif
