/* test_remind.c — reminder store + command parsing. */
#define _POSIX_C_SOURCE 200809L

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
                            "+50370000000", &days, &h, &m, to, text) == 0,
           "parse command");
        ok(!strcmp(to, "+15551234567"), "command target");
        ok(!strcmp(text, "Class in ten"), "command text");
        ok(wa_rem_parse_cmd("/reminder 08:00 maths class", "+50370000000", &days,
                            &h, &m, to, text) == 0,
           "parse command default days+to");
        ok(h == 8 && m == 0, "default command time");
        ok(!strcmp(to, "+50370000000") && !strcmp(text, "maths class"),
           "default target + text");
    }

    printf("%s\n", fails ? "some remind tests failed" : "all remind tests passed");
    return fails ? 1 : 0;
}
