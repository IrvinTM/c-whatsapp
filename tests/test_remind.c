/* test_remind.c — reminder store + command parsing. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "wa_remind.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails = 0;
static void ok(int cond, const char *msg) {
    printf("%s: %s\n", cond ? "ok" : "FAIL", msg);
    if (!cond)
        fails++;
}

/* Parse `text` at a fixed now (Fri 2026-10-30 10:15 UTC-6) and compare. */
#define NOW_FRI 1793376920
static void nl(const char *text, int want_ok, const char *date, int h, int m,
               int repeat, unsigned days, const char *want_text) {
    wa_rem_spec_t s;
    char err[256] = "", msg[512];
    int rc = wa_rem_parse_request(text, NOW_FRI, -360, "+1555", &s, err,
                                  sizeof(err));
    int good;
    if (!want_ok) {
        snprintf(msg, sizeof(msg), "nl rejects '%s' (%s)", text, err);
        ok(rc != 0 && err[0], msg);
        return;
    }
    good = rc == 0 && s.hour == h && s.min == m && s.repeat == repeat &&
           (!date || !strcmp(s.date, date)) &&
           (repeat != WA_REM_WEEKLY || s.days == days) &&
           !strcmp(s.text, want_text) && s.tz_min == -360;
    snprintf(msg, sizeof(msg),
             "nl '%s' -> rc=%d %s %02d:%02d rep=%d days=%x '%s' %s", text, rc,
             s.date, s.hour, s.min, s.repeat, s.days, s.text, err);
    ok(good, msg);
}

int main(void) {
    char tdir[] = "/tmp/cwa_rem_XXXXXX";
    char *dir = mkdtemp(tdir);
    wa_reminder_t rems[WA_REM_MAX];
    int n, id;

    if (!dir) {
        perror("mkdtemp");
        return 1;
    }

    ok(wa_rem_days_parse("Mon-Fri") ==
           ((1u << 1) | (1u << 2) | (1u << 3) | (1u << 4) | (1u << 5)),
       "parse Mon-Fri");
    ok(wa_rem_days_parse("*") == 0x7F, "parse *");
    ok(wa_rem_days_parse("Sun") == (1u << 0), "parse Sun");
    ok(wa_rem_days_parse("Mon,Wed,Fri") ==
           ((1u << 1) | (1u << 3) | (1u << 5)),
       "parse list");
    ok(wa_rem_days_parse("Nope") == 0, "reject bad day");

    {
        int h, m;
        ok(wa_rem_time_parse("07:50", &h, &m) == 0 && h == 7 && m == 50,
           "parse time");
        ok(wa_rem_time_parse("25:00", &h, &m) != 0, "reject bad time");
    }

    id = wa_rem_add(dir, wa_rem_days_parse("Mon-Fri"), 7, 50, "+15551234567",
                    "Class in 10 min");
    ok(id > 0, "add reminder");
    id = wa_rem_add(dir, 0x7F, 12, 0, "+15551234567", "Lunch");
    ok(id > 0, "add second reminder");

    n = wa_rem_load(dir, rems, WA_REM_MAX);
    ok(n == 2, "load two reminders");
    ok(n == 2 && rems[0].hour == 7 && rems[0].min == 50, "first fields");
    ok(n == 2 && !strcmp(rems[1].text, "Lunch"), "second text");

    ok(wa_rem_del(dir, rems[0].id) == 0, "delete reminder");
    n = wa_rem_load(dir, rems, WA_REM_MAX);
    ok(n == 1, "one reminder after delete");
    ok(wa_rem_del(dir, 9999) != 0, "delete missing fails");

    {
        unsigned days;
        int h, m;
        char to[WA_REM_TO_MAX], text[WA_REM_TEXT_MAX];
        ok(wa_rem_parse_cmd("/reminder Mon-Fri 07:50 +15551234567 Class in ten",
                            "+15550000000", &days, &h, &m, to, text) == 0,
           "parse command");
        ok(!strcmp(to, "+15551234567"), "command target");
        ok(!strcmp(text, "Class in ten"), "command text");
        ok(wa_rem_parse_cmd("/reminder 08:00 maths class", "+15550000000", &days,
                            &h, &m, to, text) == 0,
           "parse command default days+to");
        ok(h == 8 && m == 0, "default command time");
        ok(!strcmp(to, "+15550000000") && !strcmp(text, "maths class"),
           "default target + text");
    }

    {
        wa_rem_spec_t s;
        wa_reminder_t r;
        struct tm t;
        time_t due;
        char sched[128];

        ok(wa_rem_parse_spec("/reminder 2026-10-21 07:50 (UTC-6) weekly "
                             "Calculus class",
                             "+15550000000", 0, &s) == 0,
           "parse dated weekly command");
        ok(!strcmp(s.date, "2026-10-21") && s.hour == 7 && s.min == 50,
           "dated command date/time");
        ok(s.tz_min == -360, "dated command tz UTC-6");
        ok(s.repeat == WA_REM_WEEKLY && s.days == (1u << 3),
           "weekly uses weekday of start date");
        ok(!strcmp(s.text, "Calculus class"), "dated command title");

        memset(&r, 0, sizeof(r));
        r.id = 7;
        r.hour = 7;
        r.min = 50;
        r.tz_min = -360;
        r.repeat = WA_REM_DAILY;
        snprintf(r.date, sizeof(r.date), "%s", "2026-10-21");
        memset(&t, 0, sizeof(t));
        t.tm_year = 2026 - 1900;
        t.tm_mon = 10 - 1;
        t.tm_mday = 21;
        t.tm_hour = 13; /* 07:50 at UTC-6 */
        t.tm_min = 50;
        due = timegm(&t);
        ok(wa_rem_due(&r, due) == 1, "daily due at wall time");
        ok(wa_rem_due(&r, due + 60) == 0, "not due a minute later");
        ok(wa_rem_due(&r, due - 24 * 3600) == 0, "not due before start date");

        r.repeat = WA_REM_ONCE;
        ok(wa_rem_due(&r, due) == 1, "once due on its date");
        ok(wa_rem_due(&r, due + 24 * 3600) == 0, "once not due next day");

        r.repeat = WA_REM_WEEKLY;
        r.days = (1u << 3);
        ok(wa_rem_due(&r, due) == 1, "weekly due on Wednesday");
        ok(wa_rem_due(&r, due + 24 * 3600) == 0, "weekly not due Thursday");

        wa_rem_fmt_schedule(&r, sched, sizeof(sched));
        ok(strstr(sched, "2026-10-21 07:50 UTC-6") != NULL,
           "schedule formatting");

        ok(wa_rem_parse_spec("/reminder 09:00 UTC+5:30 daily pill",
                             "+15550000000", 0, &s) == 0,
           "parse daily with half-hour tz");
        ok(s.tz_min == 330 && s.repeat == WA_REM_DAILY, "half-hour tz + daily");
        ok(wa_rem_parse_spec("/reminder 09:00 once standup", "+1555", 0,
                             &s) == 0,
           "parse once without date");
        ok(s.repeat == WA_REM_ONCE, "once repeat");
        ok(wa_rem_parse_spec("/reminder 2026-13-01 07:50 x", "+1555", 0,
                             &s) != 0,
           "reject impossible date");
        ok(wa_rem_parse_spec("/reminder 07:50", "+1555", 0, &s) != 0,
           "reject missing title");

        ok(wa_rem_parse_spec("/reminder 2026-10-21 07:50 UTC-6 once standup",
                             "+15550000000", 0, &s) == 0,
           "parse dated once command");
        {
            int nid = wa_rem_add_spec(dir, &s);
            wa_reminder_t loaded[WA_REM_MAX];
            int ln;
            ok(nid > 0, "add spec");
            ln = wa_rem_load(dir, loaded, WA_REM_MAX);
            ok(ln >= 1, "load after add spec");
            if (ln >= 1) {
                ok(loaded[ln - 1].repeat == WA_REM_ONCE &&
                       loaded[ln - 1].tz_min == -360 &&
                       !strcmp(loaded[ln - 1].date, "2026-10-21"),
                   "stored repeat/tz/date round-trip");
            }
        }
    }

    /* chat requests: reminder WHEN TIME TEXT */
    ok(wa_rem_is_request("Remind me at 9 to x"), "trigger: Remind me");
    ok(wa_rem_is_request("/reminder 09:00 x"), "trigger: /reminder");
    ok(!wa_rem_is_request("hello there"), "no trigger: hello");
    nl("reminder every day 08:00 take pills", 1, NULL, 8, 0, WA_REM_DAILY, 0,
       "take pills");
    nl("Reminder daily 8pm journal", 1, NULL, 20, 0, WA_REM_DAILY, 0,
       "journal");
    nl("reminder every saturday 13:00 class", 1, NULL, 13, 0, WA_REM_WEEKLY,
       0x40, "class");
    nl("reminder every sat at 1 pm class", 1, NULL, 13, 0, WA_REM_WEEKLY,
       0x40, "class");
    nl("Remind me every sat at 1 pm class", 1, NULL, 13, 0, WA_REM_WEEKLY,
       0x40, "class");
    nl("reminder saturdays 10:00 call grandma", 1, NULL, 10, 0, WA_REM_WEEKLY,
       0x40, "call grandma");
    nl("reminder every weekday 7:50am class starts", 1, NULL, 7, 50,
       WA_REM_WEEKLY, 0x3E, "class starts");
    nl("reminder every weekend 10am sleep in", 1, NULL, 10, 0, WA_REM_WEEKLY,
       0x41, "sleep in");
    nl("reminder every mon,wed 18:30 gym", 1, NULL, 18, 30, WA_REM_WEEKLY,
       0x0A, "gym");
    nl("reminder every mon, wed and fri 6:30am run", 1, NULL, 6, 30,
       WA_REM_WEEKLY, 0x2A, "run");
    nl("reminder every mon-fri 07:00 standup", 1, NULL, 7, 0, WA_REM_WEEKLY,
       0x3E, "standup");
    nl("reminder today 17:45 leave", 1, "2026-10-30", 17, 45, WA_REM_ONCE, 0,
       "leave");
    nl("reminder tomorrow 9am call mom", 1, "2026-10-31", 9, 0, WA_REM_ONCE,
       0, "call mom");
    nl("reminder mon 10:00 standup", 1, "2026-11-02", 10, 0, WA_REM_ONCE, 0,
       "standup");
    nl("reminder fri 09:00 review", 1, "2026-11-06", 9, 0, WA_REM_ONCE, 0,
       "review"); /* today is Fri and 09:00 passed -> next week */
    nl("reminder 2027-01-15 08:00 pay taxes", 1, "2027-01-15", 8, 0,
       WA_REM_ONCE, 0, "pay taxes");
    nl("reminder nov 3 2pm dentist", 1, "2026-11-03", 14, 0, WA_REM_ONCE, 0,
       "dentist");
    nl("reminder 3 nov 14:30 dentist", 1, "2026-11-03", 14, 30, WA_REM_ONCE,
       0, "dentist");
    nl("reminder jan 2 09:00 new year", 1, "2027-01-02", 9, 0, WA_REM_ONCE, 0,
       "new year");
    nl("reminder in 20 minutes check the oven", 1, "2026-10-30", 10, 36,
       WA_REM_ONCE, 0, "check the oven");
    nl("Remind me in 1 minute text gf", 1, "2026-10-30", 10, 17, WA_REM_ONCE,
       0, "text gf");
    nl("reminder in 2h stretch", 1, "2026-10-30", 12, 16, WA_REM_ONCE, 0,
       "stretch");
    nl("reminder in 1h30m stretch", 1, "2026-10-30", 11, 46, WA_REM_ONCE, 0,
       "stretch");
    nl("reminder in 3 days renew", 1, "2026-11-02", 10, 16, WA_REM_ONCE, 0,
       "renew");
    /* the text is never searched for dates, times or words */
    nl("reminder every sat 13:00 Saturday, October 31 \xe2\x80\xa2 1:00 tomorrow "
       "Or dial: +503 2113",
       1, NULL, 13, 0, WA_REM_WEEKLY, 0x40,
       "Saturday, October 31 \xe2\x80\xa2 1:00 tomorrow Or dial: +503 2113");
    nl("reminder every sat 13:00 line one\nline two\n", 1, NULL, 13, 0,
       WA_REM_WEEKLY, 0x40, "line one line two");
    { /* long pasted text: kept whole up to the limit, refused beyond it */
        static char big[6000], want[3000];
        memset(want, 'x', 2000);
        want[2000] = '\0';
        snprintf(big, sizeof(big), "reminder every sat 13:00 %s", want);
        nl(big, 1, NULL, 13, 0, WA_REM_WEEKLY, 0x40, want);
        memset(big + 24, 'x', 3000);
        big[3024] = '\0';
        nl(big, 0, NULL, 0, 0, 0, 0, NULL);
    }
    nl("reminder to buy milk", 0, NULL, 0, 0, 0, 0, NULL);
    nl("remind me to call mom tomorrow at 9", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder tomorrow call mom", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder tomorrow 9 eggs", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder tomorrow 09:00", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every sunny 09:00 x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every sat", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder today 08:00 x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder 2026-01-01 08:00 x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder feb 30 08:00 x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder in five minutes x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder", 0, NULL, 0, 0, 0, 0, NULL);
    {
        wa_reminder_t r;
        char d[128];
        memset(&r, 0, sizeof(r));
        r.hour = 9;
        r.tz_min = -360;
        r.repeat = WA_REM_ONCE;
        snprintf(r.date, sizeof(r.date), "2026-10-31");
        wa_rem_describe(&r, NOW_FRI, d, sizeof(d));
        ok(!strcmp(d, "tomorrow (Sat 31 Oct) at 09:00 UTC-6"), d);
        r.repeat = WA_REM_WEEKLY;
        r.days = 0x3E;
        r.date[0] = '\0';
        wa_rem_describe(&r, NOW_FRI, d, sizeof(d));
        ok(!strcmp(d, "every weekday at 09:00 UTC-6"), d);
        ok(WA_REM_TZ == -360, "fixed timezone is UTC-6");
    }

    printf("%s\n", fails ? "some remind tests failed" : "all remind tests passed");
    return fails ? 1 : 0;
}
