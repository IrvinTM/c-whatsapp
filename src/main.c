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
#include <unistd.h>

#include "wa_auth.h"
#include "wa_qr.h"
#include "wa_remind.h"
#include "wa_socket.h"

#define CWA_VERSION "0.7.0"

static void usage(const char *argv0) {
    printf("c-whatsapp %s — WhatsApp Linked-Device client in C (Baileys port)\n\n", CWA_VERSION);
    printf("Usage:\n");
    printf("  %s [--auth-dir DIR] [--qr] [--timeout SECS] [--name PUSHNAME]\n", argv0);
    printf("  %s [--auth-dir DIR] --pair NUMBER [--timeout SECS]\n", argv0);
    printf("  %s [--auth-dir DIR] --to JID --text MSG\n", argv0);
    printf("  %s [--auth-dir DIR] --remind-add DAYS HH:MM TO TEXT...\n", argv0);
    printf("  %s [--auth-dir DIR] --remind-list\n", argv0);
    printf("  %s [--auth-dir DIR] --remind-del ID\n", argv0);
    printf("  %s [--auth-dir DIR] --daemon [--timeout SECS]\n", argv0);
    printf("  %s [--auth-dir DIR] --listen [--timeout SECS]\n", argv0);
    printf("\nOptions:\n");
    printf("  --auth-dir DIR   session dir (default: auth_info)\n");
    printf("  --qr             link a new device via QR (default when no session)\n");
    printf("  --pair NUMBER    link via 8-digit code (digits + country code)\n");
    printf("  --timeout SECS   overall run timeout (default: 180, 0 = forever)\n");
    printf("  --name NAME      push name sent in ClientPayload\n");
    printf("  --to JID         recipient (actually sends)\n");
    printf("  --text MSG       message text (actually sends)\n");
    printf("  --remind-add     add weekly reminder: DAYS=Mon-Fri|* HH:MM TO TEXT\n");
    printf("  --remind-list    list reminders\n");
    printf("  --remind-del ID  delete reminder\n");
    printf("  --daemon         keep running, send due reminders (polls 15s)\n");
    printf("  --listen         stay online, decrypt messages, fire reminders, handle /reminder\n");
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

static void on_message(const char *from, const char *text, void *user) {
    (void)user;
    printf("[msg] %s: %s\n", from, text);
    fflush(stdout);
}

int main(int argc, char **argv) {
    const char *auth_dir = "auth_info";
    const char *to = NULL;
    const char *text = NULL;
    const char *push_name = NULL;
    const char *pair_number = NULL;
    int timeout_secs = 180;
    int want_qr = 0;
    int want_daemon = 0;
    int want_listen = 0;
    int want_list = 0;
    int want_del = -1;
    const char *ra_days = NULL, *ra_time = NULL, *ra_to = NULL;
    const char *ra_text = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "--auth-dir") && i + 1 < argc) {
            auth_dir = argv[++i];
        } else if (!strcmp(argv[i], "--qr")) {
            want_qr = 1;
        } else if (!strcmp(argv[i], "--daemon")) {
            want_daemon = 1;
        } else if (!strcmp(argv[i], "--listen")) {
            want_listen = 1;
        } else if (!strcmp(argv[i], "--remind-list")) {
            want_list = 1;
        } else if (!strcmp(argv[i], "--remind-del") && i + 1 < argc) {
            want_del = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--remind-add") && i + 4 < argc) {
            ra_days = argv[++i];
            ra_time = argv[++i];
            ra_to = argv[++i];
            /* rest of argv = text words */
            {
                static char buf[WA_REM_TEXT_MAX];
                buf[0] = '\0';
                ra_text = argv[++i];
                snprintf(buf, sizeof(buf), "%s", ra_text);
                while (i + 1 < argc && argv[i + 1][0] != '-') {
                    strncat(buf, " ", sizeof(buf) - strlen(buf) - 1);
                    strncat(buf, argv[++i],
                            sizeof(buf) - strlen(buf) - 1);
                }
                /* keep static; copy into malloc for safety */
                char *cp = malloc(strlen(buf) + 1);
                if (cp)
                    strcpy(cp, buf);
                ra_text = cp ? cp : buf;
            }
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

    /* Local reminder ops (no connection needed). */
    if (want_list) {
        wa_reminder_t rems[WA_REM_MAX];
        int n = wa_rem_load(auth_dir, rems, WA_REM_MAX);
        if (n < 0) {
            fprintf(stderr, "cannot read reminders\n");
            return 1;
        }
        if (!n)
            printf("(no reminders in %s/reminders.tsv)\n", auth_dir);
        for (int i = 0; i < n; i++) {
            char sched[128];
            wa_rem_fmt_schedule(&rems[i], sched, sizeof(sched));
            printf("%d\t%s\t%s\t%s\n", rems[i].id, sched, rems[i].to,
                   rems[i].text);
        }
        return 0;
    }
    if (want_del >= 0) {
        if (wa_rem_del(auth_dir, want_del)) {
            fprintf(stderr, "no reminder id=%d\n", want_del);
            return 1;
        }
        printf("[remind] deleted id=%d\n", want_del);
        return 0;
    }
    if (ra_days) {
        unsigned days = wa_rem_days_parse(ra_days);
        int h, m;
        if (!days) {
            fprintf(stderr, "bad DAYS (try Mon-Fri or Mon,Tue,Wed or *)\n");
            return 2;
        }
        if (wa_rem_time_parse(ra_time, &h, &m)) {
            fprintf(stderr, "bad HH:MM\n");
            return 2;
        }
        int id = wa_rem_add(auth_dir, days, h, m, ra_to, ra_text);
        if (id < 0) {
            fprintf(stderr, "cannot save reminder\n");
            return 1;
        }
        printf("[remind] added id=%d %s %02d:%02d -> %s: %s\n", id, ra_days,
               h, m, ra_to, ra_text);
        return 0;
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
        /* fall through to wa_conn_run send path */
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
    opts.to_jid = to;
    opts.text = text;
    opts.daemon = want_daemon;
    opts.listen = want_listen;
    opts.on_message = on_message;
    opts.run_timeout_ms = timeout_secs * 1000;
    if (want_daemon)
        opts.run_timeout_ms = timeout_secs > 0 ? timeout_secs * 1000 : 0;

    if (want_daemon || want_listen) {
        if (!creds.me_id[0]) {
            fprintf(stderr, "[%s] no linked session; run --qr first\n",
                    want_daemon ? "daemon" : "listen");
            return 2;
        }
        printf("[%s] online%s (Ctrl-C to stop)...\n",
               want_daemon ? "daemon" : "listen",
               want_daemon ? ", polling reminders" : "");
        for (;;) {
            int rc = wa_conn_run(&creds, &opts);
            if (rc == WA_RUN_RESTART) {
                printf("[%s] restart requested, reconnecting in 3s...\n",
                       want_daemon ? "daemon" : "listen");
                sleep(3);
                continue;
            }
            if (rc == WA_RUN_TIMEOUT && opts.run_timeout_ms == 0) {
                printf("[%s] timeout?! reconnecting in 3s...\n",
                       want_daemon ? "daemon" : "listen");
                sleep(3);
                continue;
            }
            if (rc == WA_RUN_TIMEOUT) {
                printf("[timeout] no result within %d seconds\n",
                       timeout_secs);
                return 4;
            }
            printf("[%s] connection lost (rc=%d), reconnecting in 5s...\n",
                   want_daemon ? "daemon" : "listen", rc);
            sleep(5);
            /* reload creds (pairing may have updated them) */
            if (wa_auth_load(&creds, auth_dir) != 0) {
                fprintf(stderr, "[%s] cannot reload session\n",
                        want_daemon ? "daemon" : "listen");
                return 1;
            }
        }
        return 0;
    }

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
