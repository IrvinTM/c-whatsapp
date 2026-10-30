/* wa_remind.h — text-file reminder store for class notifications.
 *
 * File: <auth_dir>/reminders.tsv, one reminder per line, version 2:
 *   id<TAB>date<TAB>HH:MM<TAB>tz<TAB>repeat<TAB>days<TAB>to<TAB>text
 * date:   YYYY-MM-DD start date, or "-" for none
 * tz:     offset in minutes east of UTC (e.g. -360 = UTC-6)
 * repeat: once | daily | weekly | nag
 * days:   weekly day mask ("Mon-Fri", "*"), "-" when unused
 *
 * Version 3 adds the nag repeat, which carries three more fields:
 *   id<TAB>date<TAB>HH:MM<TAB>tz<TAB>nag<TAB>-<TAB>to<TAB>text
 *     <TAB>interval_min<TAB>next_fire_epoch<TAB>sent
 * date and HH:MM are the creation wall time; next_fire_epoch is the UTC time
 * of the next send; sent counts sends so far. Other lines are unchanged and
 * old binaries skip the unknown repeat name.
 *
 * Legacy 5-field lines (id, days, HH:MM, to, text) are still read and are
 * treated as weekly reminders in WA_REM_TZ.
 */
#ifndef WA_REMIND_H
#define WA_REMIND_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WA_REM_TO_MAX 160
#define WA_REM_TEXT_MAX 2048
#define WA_REM_MAX 256
#define WA_REM_DATE_LEN 10
/* Every new reminder uses this fixed offset (minutes east of UTC): UTC-6. */
#define WA_REM_TZ (-360)

/* Nag reminders: repeat every interval until settled, each gap jittered. */
#define WA_REM_NAG_MIN_INTERVAL 15   /* minutes */
#define WA_REM_NAG_MAX_INTERVAL 1440 /* minutes */
#define WA_REM_NAG_JITTER_S 300      /* +/- seconds around each interval */
#define WA_REM_NAG_MIN_GAP_S 300     /* never schedule closer than this */
#define WA_REM_NAG_LATE_S 120        /* later than this: rebase on now */
#define WA_REM_NAG_RETRY_S 120       /* failed send: try again after */
#define WA_REM_NAG_MAX_SENDS 24      /* then the nag removes itself */
#define WA_REM_NAG_MAX_ACTIVE 5

/* wa_rem_add_spec failures besides -1 (bad spec / IO). */
#define WA_REM_ERR_FULL (-2) /* WA_REM_MAX reminders stored */
#define WA_REM_ERR_NAGS (-3) /* WA_REM_NAG_MAX_ACTIVE nags active */

enum {
    WA_REM_ONCE = 0,
    WA_REM_DAILY = 1,
    WA_REM_WEEKLY = 2,
    WA_REM_NAG = 3
};

typedef struct {
    int id;
    unsigned days; /* weekly bitmask, bit0=Sun..bit6=Sat (tm_wday) */
    int hour;
    int min;
    int tz_min; /* minutes east of UTC (UTC-6 => -360) */
    int repeat; /* WA_REM_ONCE / DAILY / WEEKLY / NAG */
    char date[WA_REM_DATE_LEN + 1]; /* "" or YYYY-MM-DD (start date) */
    char to[WA_REM_TO_MAX];
    char text[WA_REM_TEXT_MAX];
    int interval_min;   /* WA_REM_NAG only, else 0 */
    time_t next_fire;   /* WA_REM_NAG: UTC epoch of next send, else 0 */
    int sent;           /* WA_REM_NAG: sends so far */
} wa_reminder_t;

/* Parsed "/reminder ..." command, before it is assigned an id. */
typedef struct {
    unsigned days;
    int hour;
    int min;
    int tz_min;
    int repeat;
    char date[WA_REM_DATE_LEN + 1];
    char to[WA_REM_TO_MAX];
    char text[WA_REM_TEXT_MAX];
    int interval_min;   /* WA_REM_NAG only, else 0 */
    time_t next_fire;   /* WA_REM_NAG: UTC epoch of next send, else 0 */
    int sent;           /* WA_REM_NAG: sends so far */
} wa_rem_spec_t;

/* Parse days like "Mon-Fri", "Mon,Tue,Wed", "*". Returns bitmask, 0=error. */
unsigned wa_rem_days_parse(const char *s);
/* Format bitmask back to "Mon,Tue,..." (for list). */
void wa_rem_days_format(unsigned mask, char out[64]);

/* "HH:MM" -> hour/min. Returns 0 on success. */
int wa_rem_time_parse(const char *s, int *hour, int *min);

/* "YYYY-MM-DD" -> validated. Returns 0 on success. */
int wa_rem_date_parse(const char *s, char out[WA_REM_DATE_LEN + 1]);

/* "UTC-6", "GMT+5:30", "(utc-6)", "-6" -> minutes east of UTC.
 * Returns 0 on success. */
int wa_rem_tz_parse(const char *s, int *tz_min);

/* Load all reminders from <auth_dir>/reminders.tsv. Returns count or -1. */
int wa_rem_load(const char *auth_dir, wa_reminder_t *out, int cap);
/* Append a weekly reminder in WA_REM_TZ (legacy convenience API). */
int wa_rem_add(const char *auth_dir, unsigned days, int hour, int min,
               const char *to, const char *text);
/* Append a fully specified reminder. Returns the new id, -1 (bad spec or
 * IO error), WA_REM_ERR_FULL or WA_REM_ERR_NAGS. */
int wa_rem_add_spec(const char *auth_dir, const wa_rem_spec_t *spec);
/* Delete by id (nags too: this is how "done" settles one). Returns 0 on
 * success, -1 if not found. */
int wa_rem_del(const char *auth_dir, int id);

/* Fill a stored reminder from a spec, all fields incl. the nag ones. */
void wa_rem_from_spec(wa_reminder_t *out, int id, const wa_rem_spec_t *spec);

/* True if reminder fires at `now` (minute precision, reminder's timezone).
 * Always 0 for WA_REM_NAG: those use wa_rem_nag_due. */
int wa_rem_due(const wa_reminder_t *r, time_t now);

/* Nag scheduling. Pure functions, `rnd` is any random 32-bit value. */
/* nominal + (rnd % 601 - 300) seconds, never earlier than now + MIN_GAP_S. */
time_t wa_rem_nag_jitter(time_t nominal, time_t now, uint32_t rnd);
/* Time of the send after serving r->next_fire at `now`. The base is the
 * scheduled time (no drift from polling lag), or `now` if more than
 * LATE_S late (after an outage: one catch-up send, never a burst). */
time_t wa_rem_nag_next(const wa_reminder_t *r, time_t now, uint32_t rnd);
/* 1 if r is a nag and next_fire <= now. */
int wa_rem_nag_due(const wa_reminder_t *r, time_t now);
/* Atomic compare-and-swap: sets next_fire/sent of nag `id` only if the
 * stored next_fire == expect_next (so a concurrent "done" or edit wins).
 * new_sent >= WA_REM_NAG_MAX_SENDS removes the line instead.
 * Returns 0 updated, 1 removed, -1 missing/mismatch/not a nag/IO error. */
int wa_rem_nag_advance(const char *auth_dir, int id, time_t expect_next,
                       time_t new_next, int new_sent);
/* Full outgoing message for send number r->sent (0 = first). Starts with
 * the alarm-clock emoji; the last one says it will stop. */
void wa_rem_nag_text(const wa_reminder_t *r, char *out, size_t cap);

/* Parse "/reminder ..." (see README/help for the grammar). Returns 0. */
int wa_rem_parse_spec(const char *body, const char *default_to,
                      int default_tz_min, wa_rem_spec_t *out);

/* Legacy parser kept for callers/tests: fills days/hour/min/to/text. */
int wa_rem_parse_cmd(const char *body, const char *default_to,
                     unsigned *days, int *hour, int *min,
                     char to_out[WA_REM_TO_MAX],
                     char text_out[WA_REM_TEXT_MAX]);

/* True if `text` starts with a reminder trigger ("remind", "/reminder",
 * "remindme"). */
int wa_rem_is_request(const char *text);

/* Parse a chat request in the fixed format
 *   reminder WHEN TIME TEXT
 *   reminder in DELAY TEXT
 *   reminder every INTERVAL [until done] TEXT
 * WHEN: every day | every weekday | every weekend | every sat | every mon,wed
 *       | today | tomorrow | sat | 2026-11-03 | nov 3
 * TIME: 13:00 | 1pm | 1:30 pm (optional leading "at"; a bare "1" is rejected)
 * INTERVAL: hour | half hour | 30 minutes | 2h | 1h30m | 90m (15 min to 24 h),
 *       or "hourly TEXT". It starts now and repeats (a WA_REM_NAG) until
 *       settled, so no clock time is allowed. next_fire is set one interval
 *       from `now` without jitter; the caller applies wa_rem_nag_jitter.
 * TEXT is kept as typed. "remind" and "remind me" also work as the trigger.
 * Returns 0 on success; -1 with a human hint in err otherwise. */
int wa_rem_parse_request(const char *text, time_t now, int tz_min,
                         const char *to, wa_rem_spec_t *out, char *err,
                         size_t errcap);

/* Friendly schedule, e.g. "tomorrow (Fri 31 Oct) at 09:00 UTC-6" or
 * "every weekday at 07:50 UTC-6". A nag reads "every ~1h until done
 * (3 sent), next ~11:20 UTC-6" (~Sat 07:03 when next is not today). */
void wa_rem_describe(const wa_reminder_t *r, time_t now, char *out,
                     size_t cap);

/* One-line schedule summary: "2026-10-21 07:50 UTC-6 weekly", or for a nag
 * "2026-10-30 10:15 UTC-6 every 60m next 2026-10-30 11:20 sent 0". */
void wa_rem_fmt_schedule(const wa_reminder_t *r, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* WA_REMIND_H */
