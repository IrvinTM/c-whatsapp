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

    printf("%s\n", fails ? "some remind tests failed" : "all remind tests passed");
    return fails ? 1 : 0;
}
