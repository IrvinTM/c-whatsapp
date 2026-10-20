/* wa_remind.h — tiny text-file reminder store for class notifications.
 *
 * File: <auth_dir>/reminders.tsv, one per line:
 *   id<TAB>days<TAB>HH:MM<TAB>to<TAB>text
 * days: comma list and/or ranges, e.g. Mon,Tue,Wed,Thu,Fri / Mon-Fri / *.
 * No deps, phone-friendly.
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

typedef struct {
    int id;
    unsigned days; /* bitmask, bit0=Sun..bit6=Sat (tm_wday) */
    int hour;
    int min;
    char to[WA_REM_TO_MAX];
    char text[WA_REM_TEXT_MAX];
} wa_reminder_t;

/* Parse days like "Mon-Fri", "Mon,Tue,Wed", "*". Returns bitmask, 0=error. */
unsigned wa_rem_days_parse(const char *s);
/* Format bitmask back to "Mon,Tue,..." (for list). */
void wa_rem_days_format(unsigned mask, char out[64]);

/* "HH:MM" -> hour/min. Returns 0 on success. */
int wa_rem_time_parse(const char *s, int *hour, int *min);

/* Load all reminders from <auth_dir>/reminders.tsv. Returns count or -1. */
int wa_rem_load(const char *auth_dir, wa_reminder_t *out, int cap);
/* Append one reminder, assigning id = max+1. Returns new id or -1. */
int wa_rem_add(const char *auth_dir, unsigned days, int hour, int min,
               const char *to, const char *text);
/* Delete by id. Returns 0 on success, -1 if not found. */
int wa_rem_del(const char *auth_dir, int id);

/* True if reminder fires at `now` (local time, minute precision). */
int wa_rem_due(const wa_reminder_t *r, time_t now);

/* Parse "/reminder ..." or "--remind-add ..." body.
 * Accepts: [days] HH:MM [to] text...
 *   days optional (default Mon-Fri), to optional (default sender/CLI --to).
 * Returns 0 on success. */
int wa_rem_parse_cmd(const char *body, const char *default_to,
                     unsigned *days, int *hour, int *min,
                     char to_out[WA_REM_TO_MAX],
                     char text_out[WA_REM_TEXT_MAX]);

#ifdef __cplusplus
}
#endif

#endif /* WA_REMIND_H */
