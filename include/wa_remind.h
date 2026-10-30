/* wa_remind.h — text-file reminder store for class notifications.
 *
 * File: <auth_dir>/reminders.tsv, one reminder per line, version 2:
 *   id<TAB>date<TAB>HH:MM<TAB>tz<TAB>repeat<TAB>days<TAB>to<TAB>text
 * date:   YYYY-MM-DD start date, or "-" for none
 * tz:     offset in minutes east of UTC (e.g. -360 = UTC-6)
 * repeat: once | daily | weekly
 * days:   weekly day mask ("Mon-Fri", "*"), "-" when unused
 *
 * Legacy 5-field lines (id, days, HH:MM, to, text) are still read and are
 * treated as weekly reminders in the process's local timezone.
 */
#ifndef WA_REMIND_H
#define WA_REMIND_H

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WA_REM_TO_MAX 160
#define WA_REM_TEXT_MAX 512
#define WA_REM_MAX 256
#define WA_REM_DATE_LEN 10

enum {
    WA_REM_ONCE = 0,
    WA_REM_DAILY = 1,
    WA_REM_WEEKLY = 2
};

typedef struct {
    int id;
    unsigned days; /* weekly bitmask, bit0=Sun..bit6=Sat (tm_wday) */
    int hour;
    int min;
    int tz_min; /* minutes east of UTC (UTC-6 => -360) */
    int repeat; /* WA_REM_ONCE / WA_REM_DAILY / WA_REM_WEEKLY */
    char date[WA_REM_DATE_LEN + 1]; /* "" or YYYY-MM-DD (start date) */
    char to[WA_REM_TO_MAX];
    char text[WA_REM_TEXT_MAX];
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

/* Minutes east of UTC for the process's local timezone right now. */
int wa_rem_local_offset(void);

/* Load all reminders from <auth_dir>/reminders.tsv. Returns count or -1. */
int wa_rem_load(const char *auth_dir, wa_reminder_t *out, int cap);
/* Append a weekly reminder in local time (legacy convenience API). */
int wa_rem_add(const char *auth_dir, unsigned days, int hour, int min,
               const char *to, const char *text);
/* Append a fully specified reminder. Returns new id or -1. */
int wa_rem_add_spec(const char *auth_dir, const wa_rem_spec_t *spec);
/* Delete by id. Returns 0 on success, -1 if not found. */
int wa_rem_del(const char *auth_dir, int id);

/* True if reminder fires at `now` (minute precision, reminder's timezone). */
int wa_rem_due(const wa_reminder_t *r, time_t now);

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

/* Parse a plain-language request such as
 *   "remind me tomorrow at 9am to call mom"
 *   "remind me in 20 minutes to take the pizza out"
 *   "remind me every weekday at 7:50 class starts"
 *   "remind me on friday evening to pay rent"
 *   "remind me nov 3 at 14:30 UTC-6 dentist"
 * `now` and `tz_min` resolve relative dates; `to` is the recipient.
 * Returns 0 on success; -1 with a human hint in err otherwise. */
int wa_rem_parse_natural(const char *text, time_t now, int tz_min,
                         const char *to, wa_rem_spec_t *out, char *err,
                         size_t errcap);

/* Friendly schedule, e.g. "tomorrow (Fri 31 Oct) at 09:00 UTC-6" or
 * "every weekday at 07:50 UTC-6". */
void wa_rem_describe(const wa_reminder_t *r, time_t now, char *out,
                     size_t cap);

/* Default timezone for chat requests, stored in <auth_dir>/timezone. */
int wa_rem_tz_load(const char *auth_dir, int fallback);
int wa_rem_tz_save(const char *auth_dir, int tz_min);

/* One-line schedule summary: "2026-10-21 07:50 UTC-6 weekly". */
void wa_rem_fmt_schedule(const wa_reminder_t *r, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* WA_REMIND_H */
