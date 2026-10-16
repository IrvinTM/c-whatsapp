/* c-whatsapp CLI.
 *
 * Manages the auth dir (like useMultiFileAuthState) and runs the real
 * connection flow: --qr links a new device, logged-in sessions reconnect.
 * Message sending arrives in Phase 5.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_auth.h"
#include "wa_qr.h"
#include "wa_socket.h"

#define CWA_VERSION "0.5.0"

static void usage(const char *argv0) {
    printf("c-whatsapp %s — WhatsApp Linked-Device client in C (Baileys port)\n\n", CWA_VERSION);
    printf("Usage:\n");
    printf("  %s [--auth-dir DIR] [--qr] [--timeout SECS] [--name PUSHNAME]\n", argv0);
    printf("  %s [--auth-dir DIR] --pair NUMBER [--timeout SECS]\n", argv0);
    printf("  %s [--auth-dir DIR] --to JID --text MSG\n", argv0);
    printf("\nOptions:\n");
    printf("  --auth-dir DIR   session dir (default: auth_info)\n");
    printf("  --qr             link a new device via QR (default when no session)\n");
    printf("  --pair NUMBER    link via 8-digit code (digits + country code)\n");
    printf("  --timeout SECS   overall run timeout (default: 180)\n");
    printf("  --name NAME      push name sent in ClientPayload\n");
    printf("  --to JID         recipient (Phase 5b: actually sends)\n");
    printf("  --text MSG       message text (Phase 5b: actually sends)\n");
    printf("  -h, --help       this help\n");
}

static void on_qr(const char *qr, void *user) {
    (void)user;
    printf("\n[qr] scan with WhatsApp > Linked devices:\n");
    wa_qr_print(qr);
    printf("%s\n\n", qr);
    fflush(stdout);
}

static void on_pair_code(const char *code, void *user) {
    (void)user;
    printf("\n[pair] enter this code on the phone\n");
    printf("        (WhatsApp > Linked devices > Link with phone number):\n");
    printf("        %.4s-%.4s\n\n", code, code + 4);
    fflush(stdout);
}

static void on_open(void *user) {
    (void)user;
    printf("[open] connected to WhatsApp\n");
}

static void on_close(const char *reason, void *user) {
    (void)user;
    printf("[close] %s\n", reason);
}

static void on_log(const char *msg, void *user) {
    (void)user;
    printf("[log] %s\n", msg);
}

int main(int argc, char **argv) {
    const char *auth_dir = "auth_info";
    const char *to = NULL;
    const char *text = NULL;
    const char *push_name = NULL;
    const char *pair_number = NULL;
    int timeout_secs = 180;
    int want_qr = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "--auth-dir") && i + 1 < argc) {
            auth_dir = argv[++i];
        } else if (!strcmp(argv[i], "--qr")) {
            want_qr = 1;
        } else if (!strcmp(argv[i], "--pair") && i + 1 < argc) {
            pair_number = argv[++i];
        } else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
            timeout_secs = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--name") && i + 1 < argc) {
            push_name = argv[++i];
        } else if (!strcmp(argv[i], "--to") && i + 1 < argc) {
            to = argv[++i];
        } else if (!strcmp(argv[i], "--text") && i + 1 < argc) {
            text = argv[++i];
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }
    if (!!to != !!text) {
        fprintf(stderr, "--to and --text must be given together\n");
        return 2;
    }

    wa_creds_t creds;
    int lr = wa_auth_load(&creds, auth_dir);
    if (lr == 1) {
        printf("[auth] no session in '%s', generating keys...\n", auth_dir);
        wa_creds_init(&creds);
        if (wa_creds_generate(&creds)) {
            fprintf(stderr, "[auth] key generation failed\n");
            return 1;
        }
        if (wa_auth_save(&creds, auth_dir)) {
            fprintf(stderr, "[auth] cannot save session: %s\n", strerror(errno));
            return 1;
        }
        printf("[auth] new session saved to '%s/creds.json'\n", auth_dir);
    } else if (lr == 0) {
        printf("[auth] session loaded from '%s' (registered=%d%s%s)\n", auth_dir,
               creds.registered, creds.me_id[0] ? ", me=" : "", creds.me_id);
    } else {
        fprintf(stderr, "[auth] cannot read session in '%s'\n", auth_dir);
        return 1;
    }

    if (to) {
        if (!creds.me_id[0]) {
            fprintf(stderr, "[send] no linked session; run --qr first\n");
            return 2;
        }
        printf("[send] not implemented yet (Phase 5): would send %zu bytes to %s\n",
               strlen(text), to);
        return 3;
    }

    if (pair_number) {
        size_t n = strlen(pair_number);
        int digits = n > 0 && n <= 16;
        for (size_t i = 0; i < n; i++)
            if (pair_number[i] < '0' || pair_number[i] > '9')
                digits = 0;
        if (!digits) {
            fprintf(stderr, "--pair needs digits only, with country code\n");
            return 2;
        }
        if (creds.registered) {
            fprintf(stderr, "[pair] session already linked; refusing\n");
            return 2;
        }
        /* fresh ephemeral + code on every attempt */
        if (wa_creds_gen_pairing(&creds)) {
            fprintf(stderr, "[pair] pairing key generation failed\n");
            return 1;
        }
        if (wa_auth_save(&creds, auth_dir)) {
            fprintf(stderr, "[pair] cannot save session: %s\n", strerror(errno));
            return 1;
        }
    }

    if (!want_qr && !creds.me_id[0])
        want_qr = 1; /* fresh session implies linking */
    (void)want_qr;

    wa_conn_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.on_qr = on_qr;
    opts.on_pair_code = on_pair_code;
    opts.on_open = on_open;
    opts.on_close = on_close;
    opts.on_log = on_log;
    opts.push_name = push_name;
    opts.pair_number = pair_number;
    opts.auth_dir = auth_dir;
    opts.run_timeout_ms = timeout_secs * 1000;

    int rc = wa_conn_run(&creds, &opts);
    if (rc == WA_RUN_OPEN)
        return 0;
    if (rc == WA_RUN_RESTART) {
        printf("[restart] paired; re-run to log in with the saved session.\n");
        return 0;
    }
    if (rc == WA_RUN_TIMEOUT) {
        printf("[timeout] no result within %d seconds\n", timeout_secs);
        return 4;
    }
    fprintf(stderr, "[error] connection failed\n");
    return 1;
}
