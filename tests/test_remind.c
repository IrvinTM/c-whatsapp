/* test_remind.c — reminder store + command parsing. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "wa_remind.h"

#include <stdint.h>
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
             "nl '%.100s' -> rc=%d %s %02d:%02d rep=%d days=%x '%.60s' %s", text, rc,
             s.date, s.hour, s.min, s.repeat, s.days, s.text, err);
    ok(good, msg);
}

/* Parse a nag request at NOW_FRI: interval, text, first send one interval on. */
static void nag(const char *text, int want_interval, const char *want_text) {
    wa_rem_spec_t s;
    char err[256] = "", msg[512];
    int rc = wa_rem_parse_request(text, NOW_FRI, -360, "+1555", &s, err,
                                  sizeof(err));
    int good = rc == 0 && s.repeat == WA_REM_NAG &&
               s.interval_min == want_interval &&
               s.next_fire == NOW_FRI + (time_t)want_interval * 60 &&
               s.sent == 0 && s.days == 0 && !strcmp(s.text, want_text) &&
               !strcmp(s.date, "2026-10-30") && s.hour == 10 && s.min == 15 &&
               s.tz_min == -360 && !strcmp(s.to, "+1555");
    snprintf(msg, sizeof(msg), "nag '%.100s' -> rc=%d rep=%d iv=%d next+%ld '%.60s' %s",
             text, rc, s.repeat, s.interval_min, (long)(s.next_fire - NOW_FRI),
             s.text, err);
    ok(good, msg);
}

/* A nag reminder, as the store would load it. */
static void mk_nag(wa_reminder_t *r, int id, int interval, time_t next,
                   int sent, const char *text) {
    memset(r, 0, sizeof(*r));
    r->id = id;
    r->hour = 10;
    r->min = 15;
    r->tz_min = -360;
    r->repeat = WA_REM_NAG;
    snprintf(r->date, sizeof(r->date), "%s", "2026-10-30");
    snprintf(r->to, sizeof(r->to), "%s", "+1555");
    snprintf(r->text, sizeof(r->text), "%s", text);
    r->interval_min = interval;
    r->next_fire = next;
    r->sent = sent;
}

static void mk_spec(wa_rem_spec_t *s, int nagging, const char *text) {
    memset(s, 0, sizeof(*s));
    s->tz_min = -360;
    s->hour = 10;
    s->min = 15;
    snprintf(s->date, sizeof(s->date), "%s", "2026-10-30");
    snprintf(s->to, sizeof(s->to), "%s", "+1555");
    snprintf(s->text, sizeof(s->text), "%s", text);
    if (nagging) {
        s->repeat = WA_REM_NAG;
        s->interval_min = 60;
        s->next_fire = NOW_FRI + 3600;
    } else {
        s->repeat = WA_REM_ONCE;
    }
}

static char *fresh_dir(char *tmpl) {
    char *d = mkdtemp(tmpl);
    if (!d) {
        perror("mkdtemp");
        exit(1);
    }
    return d;
}

static void write_store(const char *d, const char *body) {
    char path[600];
    FILE *f;
    snprintf(path, sizeof(path), "%s/reminders.tsv", d);
    f = fopen(path, "w");
    if (!f) {
        perror("fopen");
        exit(1);
    }
    fputs(body, f);
    fclose(f);
}

static const wa_reminder_t *find_id(const wa_reminder_t *r, int n, int id) {
    for (int i = 0; i < n; i++)
        if (r[i].id == id)
            return &r[i];
    return NULL;
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

    /* nag requests: reminder every INTERVAL TEXT */
    nag("reminder every hour take pills", 60, "take pills");
    nag("Remind me every 30 minutes stretch", 30, "stretch");
    nag("reminder every 2h drink water", 120, "drink water");
    nag("reminder every 1h30m x", 90, "x");
    nag("reminder hourly x", 60, "x");
    nag("reminder every half hour x", 30, "x");
    nag("reminder every 2 hours until done call back", 120, "call back");
    nag("reminder every hr til done x", 60, "x");
    nag("reminder every 24 hours x", 1440, "x");
    nag("reminder every 90m x", 90, "x");
    nl("reminder every day 08:00 x", 1, NULL, 8, 0, WA_REM_DAILY, 0, "x");
    nl("reminder every 5 minutes x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every minute x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every 0 minutes x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every 2 days x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every hour", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every hour at 9am x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every hour 9am x", 0, NULL, 0, 0, 0, 0, NULL);
    nl("reminder every hour from 9am x", 0, NULL, 0, 0, 0, 0, NULL);
    {
        wa_rem_spec_t sp;
        char err[256] = "";
        wa_rem_parse_request("reminder every 5 minutes x", NOW_FRI, -360, "+1",
                             &sp, err, sizeof(err));
        ok(strstr(err, "at least 15 minutes") != NULL, err);
        wa_rem_parse_request("reminder every 2 days x", NOW_FRI, -360, "+1", &sp,
                             err, sizeof(err));
        ok(strstr(err, "for longer use every day 08:00") != NULL, err);
        wa_rem_parse_request("reminder every hour at 9am x", NOW_FRI, -360, "+1",
                             &sp, err, sizeof(err));
        ok(strstr(err, "start now") != NULL, err);
        wa_rem_parse_request("reminder every banana x", NOW_FRI, -360, "+1", &sp,
                             err, sizeof(err));
        ok(strstr(err, "an interval like 2 hours") != NULL, err);
    }

    /* jitter: pure, bounded, floored */
    {
        time_t N = NOW_FRI + 3600, minv = N + 1000, maxv = N - 1000;
        uint32_t samples[] = { 0, 1, 299, 300, 301, 600, 601, 602, 12345,
                               0x7FFFFFFFu, 0xFFFFFFFEu, UINT32_MAX };
        int within = 1;
        ok(wa_rem_nag_jitter(N, NOW_FRI, 0) == N - 300, "jitter rnd 0 = -300s");
        ok(wa_rem_nag_jitter(N, NOW_FRI, 300) == N, "jitter rnd 300 = 0");
        ok(wa_rem_nag_jitter(N, NOW_FRI, 600) == N + 300, "jitter rnd 600 = +300s");
        for (uint32_t k = 0; k < 5000; k++) {
            time_t t = wa_rem_nag_jitter(N, NOW_FRI, k * 977u);
            if (t < N - 300 || t > N + 300)
                within = 0;
            if (t < minv)
                minv = t;
            if (t > maxv)
                maxv = t;
        }
        for (size_t k = 0; k < sizeof(samples) / sizeof(samples[0]); k++) {
            time_t t = wa_rem_nag_jitter(N, NOW_FRI, samples[k]);
            if (t < N - 300 || t > N + 300)
                within = 0;
        }
        ok(within, "jitter always within +-300s");
        ok(minv < N - 250 && maxv > N + 250, "jitter spreads over the range");
        ok(wa_rem_nag_jitter(NOW_FRI + 10, NOW_FRI, 300) ==
               NOW_FRI + WA_REM_NAG_MIN_GAP_S,
           "jitter floored at now + 300s");
        ok(wa_rem_nag_jitter(NOW_FRI - 5000, NOW_FRI, UINT32_MAX) >=
               NOW_FRI + WA_REM_NAG_MIN_GAP_S,
           "jitter floor beats a stale nominal");
    }

    /* nag_next: scheduled-time base, no drift, no burst after an outage */
    {
        wa_reminder_t r;
        time_t start = NOW_FRI + 3600, t;
        int gaps_ok = 1;
        mk_nag(&r, 3, 60, NOW_FRI - 10, 0, "x");
        ok(wa_rem_nag_next(&r, NOW_FRI, 300) == NOW_FRI - 10 + 3600,
           "nag_next on time counts from next_fire");
        mk_nag(&r, 3, 60, NOW_FRI - 3 * 86400, 5, "x");
        ok(wa_rem_nag_next(&r, NOW_FRI, 300) == NOW_FRI + 3600,
           "nag_next three days late counts from now (no burst)");
        mk_nag(&r, 3, 60, NOW_FRI - WA_REM_NAG_LATE_S, 5, "x");
        ok(wa_rem_nag_next(&r, NOW_FRI, 300) ==
               NOW_FRI - WA_REM_NAG_LATE_S + 3600,
           "nag_next exactly LATE_S late still counts from next_fire");
        mk_nag(&r, 3, 60, NOW_FRI - WA_REM_NAG_LATE_S - 1, 5, "x");
        ok(wa_rem_nag_next(&r, NOW_FRI, 300) == NOW_FRI + 3600,
           "nag_next one second past LATE_S rebases on now");
        mk_nag(&r, 3, 15, NOW_FRI + 5, 0, "x");
        ok(wa_rem_nag_next(&r, NOW_FRI, 0) >= NOW_FRI + 300,
           "nag_next never closer than the minimum gap");

        mk_nag(&r, 3, 45, start, 0, "x");
        t = start;
        for (int k = 0; k < 10; k++) {
            time_t nx = wa_rem_nag_next(&r, r.next_fire + 14, 300);
            if (nx - r.next_fire != 45 * 60)
                gaps_ok = 0;
            r.next_fire = nx;
            r.sent++;
        }
        ok(r.next_fire == t + 10 * 45 * 60 && gaps_ok,
           "ten sends 14s late each end at start + 10*interval");
        gaps_ok = 1;
        for (uint32_t k = 0; k < 2000; k++) {
            time_t nx;
            mk_nag(&r, 3, 60, start, 0, "x");
            nx = wa_rem_nag_next(&r, start + 3, k * 7919u);
            if (nx - start < 3600 - 300 || nx - start > 3600 + 300)
                gaps_ok = 0;
        }
        ok(gaps_ok, "each gap within interval +-300s");
    }

    /* nag_due / wa_rem_due */
    {
        wa_reminder_t r;
        time_t nf = NOW_FRI + 3600;
        mk_nag(&r, 1, 60, nf, 0, "x");
        ok(!wa_rem_nag_due(&r, nf - 1), "nag not due before next_fire");
        ok(wa_rem_nag_due(&r, nf), "nag due at next_fire");
        ok(wa_rem_nag_due(&r, nf + 5000), "nag due after next_fire");
        ok(wa_rem_due(&r, nf) == 0, "wa_rem_due is 0 for a nag");
        ok(wa_rem_due(&r, NOW_FRI - 20) == 0, "wa_rem_due 0 at creation minute");
        r.repeat = WA_REM_DAILY;
        r.next_fire = 0;
        ok(!wa_rem_nag_due(&r, nf + 99999), "nag_due 0 for non-nags");
        ok(!wa_rem_nag_due(NULL, nf), "nag_due 0 for NULL");
    }

    /* storage: round trip, advance, delete */
    {
        char t1[] = "/tmp/cwa_rem_XXXXXX";
        char *d = fresh_dir(t1);
        wa_rem_spec_t sp;
        wa_reminder_t got[WA_REM_MAX];
        const wa_reminder_t *g;
        int idn, ido, idm, cnt;
        time_t nf = NOW_FRI + 3600;

        mk_spec(&sp, 0, "plain once");
        ido = wa_rem_add_spec(d, &sp);
        mk_spec(&sp, 1, "take\tpills");
        sp.sent = 2;
        idn = wa_rem_add_spec(d, &sp);
        mk_spec(&sp, 1, "second nag");
        sp.interval_min = 90;
        idm = wa_rem_add_spec(d, &sp);
        ok(ido > 0 && idn > ido && idm > idn, "add once + two nags");
        cnt = wa_rem_load(d, got, WA_REM_MAX);
        ok(cnt == 3, "load three");
        g = find_id(got, cnt, idn);
        ok(g && g->repeat == WA_REM_NAG && g->interval_min == 60 &&
               g->next_fire == nf && g->sent == 2 && g->days == 0 &&
               !strcmp(g->date, "2026-10-30") && g->hour == 10 &&
               g->min == 15 && g->tz_min == -360 && !strcmp(g->to, "+1555"),
           "nag round-trips interval, next_fire, sent");
        ok(g && !strcmp(g->text, "take pills"), "tab in text comes back as space");
        g = find_id(got, cnt, ido);
        ok(g && g->repeat == WA_REM_ONCE && g->interval_min == 0 &&
               g->next_fire == 0 && g->sent == 0 &&
               !strcmp(g->text, "plain once"),
           "non-nag has zeroed nag fields");

        ok(wa_rem_nag_advance(d, idn, nf + 1, nf + 4000, 3) == -1,
           "advance with wrong expect_next fails");
        cnt = wa_rem_load(d, got, WA_REM_MAX);
        g = find_id(got, cnt, idn);
        ok(cnt == 3 && g && g->next_fire == nf && g->sent == 2,
           "mismatch changes nothing");
        ok(wa_rem_nag_advance(d, ido, 0, nf, 1) == -1, "advance on non-nag fails");
        ok(wa_rem_nag_advance(d, 9999, nf, nf, 1) == -1, "advance on missing id");
        ok(wa_rem_nag_advance(d, idn, nf, nf + 4000, 3) == 0, "advance updates");
        cnt = wa_rem_load(d, got, WA_REM_MAX);
        g = find_id(got, cnt, idn);
        ok(cnt == 3 && g && g->next_fire == nf + 4000 && g->sent == 3 &&
               g->interval_min == 60 && !strcmp(g->text, "take pills"),
           "advance sets next_fire/sent only");
        g = find_id(got, cnt, ido);
        ok(g && !strcmp(g->text, "plain once") && g->repeat == WA_REM_ONCE,
           "other lines untouched after advance");
        g = find_id(got, cnt, idm);
        ok(g && g->interval_min == 90 && g->next_fire == nf && g->sent == 0,
           "other nag untouched after advance");
        ok(wa_rem_nag_advance(d, idn, nf, nf + 1, 4) == -1,
           "stale expect_next after advance is refused");
        ok(wa_rem_nag_advance(d, idn, nf + 4000, nf + 8000,
                              WA_REM_NAG_MAX_SENDS) == 1,
           "advance past MAX_SENDS removes the nag");
        cnt = wa_rem_load(d, got, WA_REM_MAX);
        ok(cnt == 2 && !find_id(got, cnt, idn) && find_id(got, cnt, ido) &&
               find_id(got, cnt, idm),
           "removed line gone, others kept");
        ok(wa_rem_del(d, idm) == 0, "del works on a nag");
        cnt = wa_rem_load(d, got, WA_REM_MAX);
        g = find_id(got, cnt, ido);
        ok(cnt == 1 && g && !strcmp(g->text, "plain once"),
           "other lines untouched after del");
        ok(wa_rem_del(d, idm) == -1, "del of a settled nag fails");
    }

    /* back-compat: older files still load, one bad nag line is skipped */
    {
        char t2[] = "/tmp/cwa_rem_XXXXXX";
        char *d = fresh_dir(t2);
        wa_reminder_t got[WA_REM_MAX];
        const wa_reminder_t *g;
        int cnt;
        write_store(d,
            "1\tMon-Fri\t07:50\t+15551234567\tlegacy class\n"
            "2\t2026-10-21\t07:50\t-360\tonce\t-\t+1555\tstandup\n"
            "3\t-\t08:00\t-360\tdaily\t-\t+1555\tpills\n"
            "4\t2026-10-21\t07:50\t-360\tweekly\tWed\t+1555\tcalc\n"
            "5\t-\t09:00\t-360\tdaily\t-\t+1555\ta\tb\n"
            "6\t2026-10-30\t10:15\t-360\tnag\t-\t+1555\tbad\t3\t1793380520\t0\n"
            "7\t2026-10-30\t10:15\t-360\tnag\t-\t+1555\ttake pills\t60\t"
            "1793380520\t4\n"
            "8\t2026-10-30\t10:15\t-360\tnag\t-\t+1555\ttoo few fields\n"
            "9\t2026-10-30\t10:15\t-360\tmonthly\t-\t+1555\tfuture kind\n");
        cnt = wa_rem_load(d, got, WA_REM_MAX);
        ok(cnt == 6, "load skips the bad nag, the short nag and unknown kinds");
        ok(find_id(got, cnt, 1) && find_id(got, cnt, 1)->repeat == WA_REM_WEEKLY &&
               find_id(got, cnt, 1)->tz_min == WA_REM_TZ,
           "legacy 5-field line unchanged");
        ok(find_id(got, cnt, 2) && find_id(got, cnt, 2)->repeat == WA_REM_ONCE &&
               find_id(got, cnt, 3) && find_id(got, cnt, 3)->repeat == WA_REM_DAILY &&
               find_id(got, cnt, 4) && find_id(got, cnt, 4)->days == (1u << 3),
           "v2 once/daily/weekly lines unchanged");
        g = find_id(got, cnt, 5);
        ok(g && !strncmp(g->text, "a", 1) && strchr(g->text, 'b'),
           "v2 line with a tab in the text still loads");
        ok(!find_id(got, cnt, 6) && !find_id(got, cnt, 8), "bad nag lines skipped");
        g = find_id(got, cnt, 7);
        ok(g && g->interval_min == 60 && g->next_fire == 1793380520 &&
               g->sent == 4 && !strcmp(g->text, "take pills"),
           "valid nag line loads");
        ok(wa_rem_del(d, 3) == 0, "del one line");
        cnt = wa_rem_load(d, got, WA_REM_MAX);
        ok(cnt == 5 && !find_id(got, cnt, 3) && find_id(got, cnt, 1) &&
               find_id(got, cnt, 2) && find_id(got, cnt, 4) &&
               find_id(got, cnt, 5) && find_id(got, cnt, 7),
           "the rest survive a delete");
        g = find_id(got, cnt, 7);
        ok(g && g->interval_min == 60 && g->sent == 4 &&
               !strcmp(g->text, "take pills"),
           "nag survives a rewrite");
    }

    /* limits */
    {
        char t3[] = "/tmp/cwa_rem_XXXXXX", t4[] = "/tmp/cwa_rem_XXXXXX";
        char *d = fresh_dir(t3), *d2 = fresh_dir(t4);
        wa_rem_spec_t sp;
        wa_reminder_t got[WA_REM_MAX];
        static char big[WA_REM_MAX * 64 + 64];
        size_t off = 0;
        int okc = 1, id;

        for (int k = 0; k < WA_REM_NAG_MAX_ACTIVE; k++) {
            mk_spec(&sp, 1, "nag");
            if (wa_rem_add_spec(d, &sp) <= 0)
                okc = 0;
        }
        ok(okc, "five nags succeed");
        mk_spec(&sp, 1, "nag six");
        ok(wa_rem_add_spec(d, &sp) == WA_REM_ERR_NAGS, "sixth nag refused");
        mk_spec(&sp, 0, "still fine");
        ok(wa_rem_add_spec(d, &sp) > 0, "a non-nag still fits beside five nags");
        wa_rem_del(d, 2);
        mk_spec(&sp, 1, "nag again");
        ok(wa_rem_add_spec(d, &sp) > 0, "settling a nag frees a slot");
        mk_spec(&sp, 1, "bad");
        sp.interval_min = 5;
        ok(wa_rem_add_spec(d2, &sp) == -1, "add rejects a too-short interval");
        sp.interval_min = 1441;
        ok(wa_rem_add_spec(d2, &sp) == -1, "add rejects a too-long interval");
        sp.interval_min = 60;
        sp.next_fire = 0;
        ok(wa_rem_add_spec(d2, &sp) == -1, "add rejects next_fire 0");

        for (int k = 1; k <= WA_REM_MAX; k++)
            off += (size_t)snprintf(big + off, sizeof(big) - off,
                                    "%d\t-\t08:00\t-360\tdaily\t-\t+1555\tr%d\n",
                                    k, k);
        write_store(d2, big);
        ok(wa_rem_load(d2, got, WA_REM_MAX) == WA_REM_MAX, "256 lines load");
        mk_spec(&sp, 0, "one too many");
        ok(wa_rem_add_spec(d2, &sp) == WA_REM_ERR_FULL, "full store refused");
        mk_spec(&sp, 1, "nag too many");
        ok(wa_rem_add_spec(d2, &sp) == WA_REM_ERR_FULL, "full store refuses nags");
        ok(wa_rem_load(d2, got, WA_REM_MAX) == WA_REM_MAX, "full store intact");
        ok(wa_rem_del(d2, 7) == 0, "del from a full store");
        mk_spec(&sp, 0, "now it fits");
        id = wa_rem_add_spec(d2, &sp);
        ok(id == WA_REM_MAX + 1, "slot frees up after del");
        ok(wa_rem_load(d2, got, WA_REM_MAX) == WA_REM_MAX, "still 256 after refill");
    }

    /* describe / fmt_schedule / nag_text */
    {
        wa_reminder_t r;
        char d[160], f[128];
        time_t nxt = NOW_FRI + 65 * 60;          /* Fri 11:20 UTC-6 */
        time_t sat = NOW_FRI - 20 + 74880;       /* Sat 07:03 UTC-6 */
        mk_nag(&r, 4, 60, nxt, 0, "x");
        wa_rem_describe(&r, NOW_FRI, d, sizeof(d));
        ok(!strcmp(d, "every ~1h until done, next ~11:20 UTC-6"), d);
        mk_nag(&r, 4, 90, nxt, 0, "x");
        wa_rem_describe(&r, NOW_FRI, d, sizeof(d));
        ok(!strcmp(d, "every ~1h30m until done, next ~11:20 UTC-6"), d);
        mk_nag(&r, 4, 30, nxt, 0, "x");
        wa_rem_describe(&r, NOW_FRI, d, sizeof(d));
        ok(!strcmp(d, "every ~30 min until done, next ~11:20 UTC-6"), d);
        mk_nag(&r, 4, 1440, nxt, 0, "x");
        wa_rem_describe(&r, NOW_FRI, d, sizeof(d));
        ok(!strcmp(d, "every ~24h until done, next ~11:20 UTC-6"), d);
        mk_nag(&r, 4, 60, sat, 3, "x");
        wa_rem_describe(&r, NOW_FRI, d, sizeof(d));
        ok(!strcmp(d, "every ~1h until done (3 sent), next ~Sat 07:03 UTC-6"), d);
        mk_nag(&r, 4, 60, sat, 0, "x");
        wa_rem_describe(&r, NOW_FRI, d, sizeof(d));
        ok(!strcmp(d, "every ~1h until done, next ~Sat 07:03 UTC-6"), d);

        mk_nag(&r, 4, 60, nxt, 0, "x");
        wa_rem_fmt_schedule(&r, f, sizeof(f));
        ok(!strcmp(f, "2026-10-30 10:15 UTC-6 every 60m next 2026-10-30 11:20 "
                      "sent 0"), f);
        mk_nag(&r, 4, 90, sat, 3, "x");
        wa_rem_fmt_schedule(&r, f, sizeof(f));
        ok(!strcmp(f, "2026-10-30 10:15 UTC-6 every 90m next 2026-10-31 07:03 "
                      "sent 3"), f);
        mk_nag(&r, 4, 30, nxt, 12, "x");
        wa_rem_fmt_schedule(&r, f, sizeof(f));
        ok(!strcmp(f, "2026-10-30 10:15 UTC-6 every 30m next 2026-10-30 11:20 "
                      "sent 12"), f);
    }
    {
        wa_reminder_t r;
        char m[WA_REM_TEXT_MAX + 256], seen[4][WA_REM_TEXT_MAX + 256];
        static const char ALARM[] = "\xe2\x8f\xb0 ";
        mk_nag(&r, 7, 60, NOW_FRI, 0, "take pills");
        wa_rem_nag_text(&r, m, sizeof(m));
        ok(!strncmp(m, ALARM, strlen(ALARM)) && strstr(m, "take pills") &&
               strstr(m, "done 7"),
           "nag_text first send: emoji, text, done N");
        for (int k = 1; k <= 3; k++) {
            mk_nag(&r, 7, 60, NOW_FRI, k, "take pills");
            wa_rem_nag_text(&r, seen[k], sizeof(seen[k]));
            ok(!strncmp(seen[k], ALARM, strlen(ALARM)) &&
                   strstr(seen[k], "take pills") && strstr(seen[k], "done 7"),
               "nag_text middle send: emoji, text, done N");
        }
        ok(strcmp(seen[1], seen[2]) && strcmp(seen[2], seen[3]) &&
               strcmp(seen[1], seen[3]) && strcmp(seen[1], m),
           "sent 1,2,3 give different wording");
        mk_nag(&r, 7, 60, NOW_FRI, WA_REM_NAG_MAX_SENDS - 1, "take pills");
        wa_rem_nag_text(&r, m, sizeof(m));
        ok(!strncmp(m, ALARM, strlen(ALARM)) && strstr(m, "Last") &&
               strstr(m, "take pills") && strstr(m, "#7") && !strstr(m, "done"),
           "nag_text last send says Last, no done");
        mk_nag(&r, 7, 60, NOW_FRI, 0, "\xe2\x80\xa2 long text");
        wa_rem_nag_text(&r, m, 6);
        wa_rem_nag_text(&r, m, 6);
        ok(!strcmp(m, ALARM), "nag_text truncates to cap");
        wa_rem_nag_text(&r, m, 7);
        ok(!strcmp(m, ALARM), "nag_text does not cut a UTF-8 character in half");
        wa_rem_nag_text(&r, m, 1);
        ok(m[0] == '\0', "nag_text with cap 1 is empty");
    }

    printf("%s\n", fails ? "some remind tests failed" : "all remind tests passed");
    return fails ? 1 : 0;
}
