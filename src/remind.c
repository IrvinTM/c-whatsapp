/* wa_remind.c — text-file reminder store (see wa_remind.h). */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "wa_remind.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *DNAMES[] = { "Sun", "Mon", "Tue", "Wed",
                                "Thu", "Fri", "Sat" };

static const char *REPEAT_NAMES[] = { "once", "daily", "weekly" };

static int day_index(const char *s) {
    char low[8];
    size_t i;
    for (i = 0; i < 3 && s[i]; i++)
        low[i] = (char)tolower((unsigned char)s[i]);
    low[i] = '\0';
    for (int d = 0; d < 7; d++) {
        char want[8];
        for (int k = 0; k < 3; k++)
            want[k] = (char)tolower((unsigned char)DNAMES[d][k]);
        want[3] = '\0';
        if (!strcmp(low, want))
            return d;
    }
    return -1;
}

unsigned wa_rem_days_parse(const char *s) {
    unsigned mask = 0;
    char tmp[128];
    if (!s || !*s)
        return 0;
    if (!strcmp(s, "*") || !strcmp(s, "daily") || !strcmp(s, "all")) {
        return 0x7F;
    }
    snprintf(tmp, sizeof(tmp), "%s", s);
    /* split on comma/space */
    for (char *tok = strtok(tmp, ", ;"); tok; tok = strtok(NULL, ", ;")) {
        char *dash = strchr(tok, '-');
        if (dash) {
            *dash = '\0';
            int a = day_index(tok);
            int b = day_index(dash + 1);
            if (a < 0 || b < 0)
                return 0;
            int d = a;
            for (;;) {
                mask |= (unsigned)(1u << d);
                if (d == b)
                    break;
                d = (d + 1) % 7;
            }
        } else {
            int d = day_index(tok);
            if (d < 0)
                return 0;
            mask |= (unsigned)(1u << d);
        }
    }
    return mask;
}

void wa_rem_days_format(unsigned mask, char out[64]) {
    out[0] = '\0';
    if (mask == 0x7F) {
        snprintf(out, 64, "*");
        return;
    }
    for (int d = 0; d < 7; d++) {
        if (mask & (1u << d)) {
            if (out[0])
                strcat(out, ",");
            strcat(out, DNAMES[d]);
        }
    }
}

int wa_rem_time_parse(const char *s, int *hour, int *min) {
    int h, m;
    if (!s || sscanf(s, "%d:%d", &h, &m) != 2)
        return -1;
    if (h < 0 || h > 23 || m < 0 || m > 59)
        return -1;
    *hour = h;
    *min = m;
    return 0;
}

int wa_rem_date_parse(const char *s, char out[WA_REM_DATE_LEN + 1]) {
    static const int mdays[] = { 31, 28, 31, 30, 31, 30,
                                 31, 31, 30, 31, 30, 31 };
    int y, m, d, dim, leap;
    if (!s || strlen(s) != 10 || s[4] != '-' || s[7] != '-')
        return -1;
    if (sscanf(s, "%4d-%2d-%2d", &y, &m, &d) != 3)
        return -1;
    if (y < 1970 || y > 9999 || m < 1 || m > 12 || d < 1)
        return -1;
    leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
    dim = mdays[m - 1] + (m == 2 && leap);
    if (d > dim)
        return -1;
    snprintf(out, WA_REM_DATE_LEN + 1, "%04d-%02d-%02d", y, m, d);
    return 0;
}

int wa_rem_tz_parse(const char *s, int *tz_min) {
    char b[32];
    size_t n = 0;
    const char *p;
    int sign = 1, hh = 0, mm = 0, digits = 0;
    if (!s || !tz_min)
        return -1;
    for (const char *q = s; *q && n + 1 < sizeof(b); q++) {
        if (*q == '(' || *q == ')' || isspace((unsigned char)*q))
            continue;
        b[n++] = *q;
    }
    b[n] = '\0';
    p = b;
    if (!strncasecmp(p, "utc", 3) || !strncasecmp(p, "gmt", 3))
        p += 3;
    if (!*p) {
        *tz_min = 0;
        return 0;
    }
    if (*p == '+') {
        p++;
    } else if (*p == '-') {
        sign = -1;
        p++;
    } else {
        return -1;
    }
    while (isdigit((unsigned char)*p) && digits < 2) {
        hh = hh * 10 + (*p - '0');
        p++;
        digits++;
    }
    if (!digits)
        return -1;
    if (*p == ':') {
        int md = 0;
        p++;
        while (isdigit((unsigned char)*p) && md < 2) {
            mm = mm * 10 + (*p - '0');
            p++;
            md++;
        }
        if (!md)
            return -1;
    }
    if (*p)
        return -1; /* trailing junk */
    if (hh > 14 || mm > 59 || (hh == 14 && mm > 0))
        return -1;
    *tz_min = sign * (hh * 60 + mm);
    return 0;
}

/* Wall-clock tm for a timestamp in the reminder's fixed UTC offset. */
static void wall_tm(int tz_min, time_t now, struct tm *out) {
    time_t shifted = now + (time_t)tz_min * 60;
    gmtime_r(&shifted, out);
}

/* Weekday (0=Sun) of a YYYY-MM-DD date, -1 on bad input. */
static int date_weekday(const char *date) {
    struct tm dt;
    time_t t;
    memset(&dt, 0, sizeof(dt));
    if (sscanf(date, "%4d-%2d-%2d", &dt.tm_year, &dt.tm_mon, &dt.tm_mday) != 3)
        return -1;
    dt.tm_year -= 1900;
    dt.tm_mon -= 1;
    dt.tm_isdst = 0;
    t = timegm(&dt);
    if (t == (time_t)-1)
        return -1;
    gmtime_r(&t, &dt);
    return dt.tm_wday;
}

static void rem_path(const char *auth_dir, char out[512]) {
    snprintf(out, 512, "%s/reminders.tsv", auth_dir ? auth_dir : "auth_info");
}

/* Map a repeat name to the enum, -1 if unknown. */
static int repeat_index(const char *s) {
    for (int i = 0; i < 3; i++)
        if (!strcmp(s, REPEAT_NAMES[i]))
            return i;
    return -1;
}

int wa_rem_load(const char *auth_dir, wa_reminder_t *out, int cap) {
    char path[512];
    FILE *f;
    char *line = NULL;
    size_t ll = 0;
    ssize_t n;
    int cnt = 0;
    rem_path(auth_dir, path);
    f = fopen(path, "r");
    if (!f)
        return 0; /* no file yet -> empty */
    while ((n = getline(&line, &ll, f)) >= 0) {
        wa_reminder_t r;
        char *fld[8];
        int nf = 0;
        char *p;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (!n || line[0] == '#')
            continue;
        memset(&r, 0, sizeof(r));
        p = line;
        while (nf < 8) {
            fld[nf++] = p;
            p = strchr(p, '\t');
            if (!p)
                break;
            *p++ = '\0';
        }
        if (nf == 8) {
            /* v2: id date hh:mm tz repeat days to text */
            char hm[16];
            r.id = atoi(fld[0]);
            if (strcmp(fld[1], "-"))
                snprintf(r.date, sizeof(r.date), "%s", fld[1]);
            snprintf(hm, sizeof(hm), "%s", fld[2]);
            r.tz_min = atoi(fld[3]);
            r.repeat = repeat_index(fld[4]);
            if (r.repeat < 0)
                continue;
            if (strcmp(fld[5], "-"))
                r.days = wa_rem_days_parse(fld[5]);
            if (wa_rem_time_parse(hm, &r.hour, &r.min))
                continue;
            snprintf(r.to, sizeof(r.to), "%s", fld[6]);
            snprintf(r.text, sizeof(r.text), "%s", fld[7]);
        } else if (nf == 5) {
            /* legacy: id days hh:mm to text (weekly, server local time) */
            char hm[16];
            r.id = atoi(fld[0]);
            r.days = wa_rem_days_parse(fld[1]);
            if (!r.days && strcmp(fld[1], "*"))
                continue;
            snprintf(hm, sizeof(hm), "%s", fld[2]);
            if (wa_rem_time_parse(hm, &r.hour, &r.min))
                continue;
            snprintf(r.to, sizeof(r.to), "%s", fld[3]);
            snprintf(r.text, sizeof(r.text), "%s", fld[4]);
            r.repeat = WA_REM_WEEKLY;
            r.tz_min = WA_REM_TZ;
        } else {
            continue;
        }
        if (!r.to[0] || !r.text[0])
            continue;
        if (cnt < cap)
            out[cnt++] = r;
    }
    free(line);
    fclose(f);
    return cnt;
}

int wa_rem_add_spec(const char *auth_dir, const wa_rem_spec_t *s) {
    char path[512], ds[64];
    wa_reminder_t cur[WA_REM_MAX];
    int n, nid = 1;
    FILE *f;
    if (!s || !s->to[0] || !s->text[0])
        return -1;
    if (s->hour < 0 || s->hour > 23 || s->min < 0 || s->min > 59)
        return -1;
    n = wa_rem_load(auth_dir, cur, WA_REM_MAX);
    for (int i = 0; i < n; i++)
        if (cur[i].id >= nid)
            nid = cur[i].id + 1;
    rem_path(auth_dir, path);
    f = fopen(path, "a");
    if (!f)
        return -1;
    if (s->repeat == WA_REM_WEEKLY)
        wa_rem_days_format(s->days, ds);
    else
        snprintf(ds, sizeof(ds), "-");
    fprintf(f, "%d\t%s\t%02d:%02d\t%d\t%s\t%s\t%s\t%s\n", nid,
            s->date[0] ? s->date : "-", s->hour, s->min, s->tz_min,
            s->repeat >= 0 && s->repeat <= 2 ? REPEAT_NAMES[s->repeat] : "once",
            ds, s->to, s->text);
    fclose(f);
    return nid;
}

int wa_rem_add(const char *auth_dir, unsigned days, int hour, int min,
               const char *to, const char *text) {
    wa_rem_spec_t s;
    if (!days || !to || !to[0] || !text || !text[0])
        return -1;
    memset(&s, 0, sizeof(s));
    s.days = days;
    s.hour = hour;
    s.min = min;
    s.repeat = WA_REM_WEEKLY;
    s.tz_min = WA_REM_TZ;
    snprintf(s.to, sizeof(s.to), "%s", to);
    snprintf(s.text, sizeof(s.text), "%s", text);
    return wa_rem_add_spec(auth_dir, &s);
}

int wa_rem_del(const char *auth_dir, int id) {
    char path[512], tmp[520];
    wa_reminder_t cur[WA_REM_MAX];
    int n, found = 0;
    FILE *f;
    n = wa_rem_load(auth_dir, cur, WA_REM_MAX);
    for (int i = 0; i < n; i++)
        if (cur[i].id == id)
            found = 1;
    if (!found)
        return -1;
    rem_path(auth_dir, path);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f)
        return -1;
    for (int i = 0; i < n; i++) {
        char ds[64];
        if (cur[i].id == id)
            continue;
        if (cur[i].repeat == WA_REM_WEEKLY)
            wa_rem_days_format(cur[i].days, ds);
        else
            snprintf(ds, sizeof(ds), "-");
        fprintf(f, "%d\t%s\t%02d:%02d\t%d\t%s\t%s\t%s\t%s\n", cur[i].id,
                cur[i].date[0] ? cur[i].date : "-", cur[i].hour, cur[i].min,
                cur[i].tz_min, REPEAT_NAMES[cur[i].repeat], ds, cur[i].to,
                cur[i].text);
    }
    fclose(f);
    rename(tmp, path);
    return 0;
}

int wa_rem_due(const wa_reminder_t *r, time_t now) {
    struct tm w;
    char today[32];
    if (!r)
        return 0;
    wall_tm(r->tz_min, now, &w);
    if (w.tm_hour != r->hour || w.tm_min != r->min)
        return 0;
    snprintf(today, sizeof(today), "%04d-%02d-%02d", w.tm_year + 1900,
             w.tm_mon + 1, w.tm_mday);
    if (r->date[0] && strcmp(today, r->date) < 0)
        return 0;
    switch (r->repeat) {
    case WA_REM_ONCE:
        return !r->date[0] || !strcmp(today, r->date);
    case WA_REM_DAILY:
        return 1;
    case WA_REM_WEEKLY:
        return (r->days & (1u << w.tm_wday)) != 0;
    default:
        return 0;
    }
}

/* Shaped like YYYY-MM-DD even if the value is invalid. */
static int looks_like_date(const char *t) {
    size_t n = strlen(t);
    if (n != 10 || t[4] != '-' || t[7] != '-')
        return 0;
    for (size_t i = 0; i < n; i++)
        if (i != 4 && i != 7 && !isdigit((unsigned char)t[i]))
            return 0;
    return 1;
}

/* Is this token a destination (phone number or JID)? */
static int is_to_token(const char *t) {
    if (!t || !*t)
        return 0;
    if (strchr(t, '@'))
        return 1;
    for (const char *p = t; *p; p++) {
        if (*p == '+' && p == t)
            continue;
        if (*p < '0' || *p > '9')
            return 0;
    }
    return strlen(t) >= 7;
}

/* Recognise a repeat spec token; returns enum or -1. */
static int repeat_token(const char *t, unsigned *days, int *has_days) {
    unsigned m;
    if (!strcasecmp(t, "once") || !strcasecmp(t, "single") ||
        !strcasecmp(t, "1x"))
        return WA_REM_ONCE;
    if (!strcasecmp(t, "daily") || !strcasecmp(t, "everyday") ||
        !strcasecmp(t, "every-day"))
        return WA_REM_DAILY;
    if (!strcasecmp(t, "weekly")) {
        *has_days = 0;
        return WA_REM_WEEKLY;
    }
    if (!strcasecmp(t, "weekdays")) {
        *days = wa_rem_days_parse("Mon-Fri");
        *has_days = 1;
        return WA_REM_WEEKLY;
    }
    m = wa_rem_days_parse(t);
    if (m) {
        *days = m;
        *has_days = 1;
        return WA_REM_WEEKLY;
    }
    return -1;
}

int wa_rem_parse_spec(const char *body, const char *default_to,
                      int default_tz_min, wa_rem_spec_t *out) {
    char tmp[1024];
    char *toks[96];
    int nt = 0, have_time = 0, have_rep = 0, have_days = 0, have_to = 0;
    if (!body || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->repeat = -1;
    out->tz_min = default_tz_min;
    snprintf(tmp, sizeof(tmp), "%s", body);
    {
        const char *p = tmp;
        if (!strncmp(p, "/reminder", 9))
            p += 9;
        memmove(tmp, p, strlen(p) + 1);
    }
    for (char *t = strtok(tmp, " \t"); t && nt < 96; t = strtok(NULL, " \t"))
        toks[nt++] = t;
    for (int i = 0; i < nt; i++) {
        char *t = toks[i];
        char clean[128];
        size_t cl = strlen(t);
        int r;
        /* strip a single pair of surrounding parentheses */
        if (cl >= 2 && t[0] == '(' && t[cl - 1] == ')') {
            snprintf(clean, sizeof(clean), "%.*s", (int)(cl - 2), t + 1);
            t = clean;
        }
        if (!out->date[0]) {
            if (wa_rem_date_parse(t, out->date) == 0)
                continue;
            if (looks_like_date(t))
                return -1;
        }
        if (!have_time && wa_rem_time_parse(t, &out->hour, &out->min) == 0) {
            have_time = 1;
            continue;
        }
        {
            int tz;
            if (wa_rem_tz_parse(t, &tz) == 0) {
                out->tz_min = tz;
                continue;
            }
        }
        if (!have_rep) {
            if (!strcasecmp(t, "repeat") || !strcasecmp(t, "repeats") ||
                !strcasecmp(t, "every"))
                continue; /* modifier: frequency follows */
            r = repeat_token(t, &out->days, &have_days);
            if (r >= 0) {
                out->repeat = r;
                have_rep = 1;
                continue;
            }
        }
        if (!have_to && is_to_token(t)) {
            snprintf(out->to, sizeof(out->to), "%s", t);
            have_to = 1;
            continue;
        }
        if (out->text[0])
            strncat(out->text, " ",
                    sizeof(out->text) - strlen(out->text) - 1);
        strncat(out->text, t, sizeof(out->text) - strlen(out->text) - 1);
    }
    if (!have_time || !out->text[0])
        return -1;
    if (have_to) {
        /* explicit recipient already set */
    } else if (default_to && default_to[0]) {
        snprintf(out->to, sizeof(out->to), "%s", default_to);
    } else {
        return -1;
    }
    if (!have_rep) {
        if (!out->date[0]) {
            /* legacy default: weekdays at that time */
            out->repeat = WA_REM_WEEKLY;
            out->days = wa_rem_days_parse("Mon-Fri");
            have_days = 1;
        } else {
            out->repeat = WA_REM_ONCE;
        }
    } else if (out->repeat == WA_REM_WEEKLY && !have_days) {
        /* "weekly" without a day list: use the start date's weekday, or
         * today's weekday in the reminder's timezone. */
        struct tm w;
        time_t now = time(NULL);
        wall_tm(out->tz_min, now, &w);
        if (out->date[0]) {
            int wd = date_weekday(out->date);
            if (wd >= 0)
                out->days = (unsigned)(1u << wd);
        }
        if (!out->days)
            out->days = (unsigned)(1u << w.tm_wday);
        have_days = 1;
    }
    if (out->repeat == WA_REM_WEEKLY && !out->days)
        return -1;
    return 0;
}

int wa_rem_parse_cmd(const char *body, const char *default_to,
                     unsigned *days, int *hour, int *min,
                     char to_out[WA_REM_TO_MAX],
                     char text_out[WA_REM_TEXT_MAX]) {
    wa_rem_spec_t s;
    if (!days || !hour || !min || !to_out || !text_out)
        return -1;
    if (wa_rem_parse_spec(body, default_to, WA_REM_TZ, &s))
        return -1;
    if (s.repeat != WA_REM_WEEKLY)
        return -1;
    *days = s.days;
    *hour = s.hour;
    *min = s.min;
    snprintf(to_out, WA_REM_TO_MAX, "%s", s.to);
    snprintf(text_out, WA_REM_TEXT_MAX, "%s", s.text);
    return 0;
}

void wa_rem_fmt_schedule(const wa_reminder_t *r, char *out, size_t cap) {
    char tz[16], rep[64];
    int off;
    if (!r || !out || !cap)
        return;
    off = r->tz_min;
    if (off == 0)
        snprintf(tz, sizeof(tz), "UTC");
    else
        snprintf(tz, sizeof(tz), "UTC%c%d:%02d", off < 0 ? '-' : '+',
                 abs(off) / 60, abs(off) % 60);
    if (r->repeat == WA_REM_ONCE)
        snprintf(rep, sizeof(rep), "once");
    else if (r->repeat == WA_REM_DAILY)
        snprintf(rep, sizeof(rep), "daily");
    else
        wa_rem_days_format(r->days, rep);
    if (r->date[0])
        snprintf(out, cap, "%s %02d:%02d %s %s", r->date, r->hour, r->min,
                 tz, rep);
    else
        snprintf(out, cap, "%02d:%02d %s %s", r->hour, r->min, tz, rep);
}

/* ---------------- chat requests ---------------- */

#define NL_MAX_TOK 96

typedef struct {
    char *orig[NL_MAX_TOK]; /* token as typed (for the reminder text) */
    char low[NL_MAX_TOK][48]; /* lowercased, edge punctuation stripped */
    int n;
} nl_toks_t;

static void nl_tokenize(char *buf, nl_toks_t *t) {
    memset(t, 0, sizeof(*t));
    for (char *s = strtok(buf, " \t\r\n"); s && t->n < NL_MAX_TOK;
         s = strtok(NULL, " \t\r\n")) {
        char *lw = t->low[t->n];
        size_t a = 0, b = strlen(s), k = 0;
        while (a < b && strchr("\"'(", s[a]))
            a++;
        while (b > a && strchr(",.!?;:\"')", s[b - 1]))
            b--;
        for (size_t i = a; i < b && k + 1 < sizeof(t->low[0]); i++)
            lw[k++] = (char)tolower((unsigned char)s[i]);
        lw[k] = '\0';
        t->orig[t->n++] = s;
    }
}

static const char *nl_at(const nl_toks_t *t, int i) {
    return (i >= 0 && i < t->n) ? t->low[i] : "";
}

static int nl_is(const char *w, const char *const *list) {
    for (; *list; list++)
        if (!strcmp(w, *list))
            return 1;
    return 0;
}

/* Full or short weekday name (optionally plural) -> 0..6, else -1. */
static int nl_weekday(const char *w, int *plural) {
    static const char *const names[7][4] = {
        { "sunday", "sun", NULL }, { "monday", "mon", NULL },
        { "tuesday", "tue", "tues", NULL }, { "wednesday", "wed", NULL },
        { "thursday", "thu", "thur", "thurs" }, { "friday", "fri", NULL },
        { "saturday", "sat", NULL },
    };
    char base[48];
    size_t n = strlen(w);
    if (plural)
        *plural = 0;
    snprintf(base, sizeof(base), "%s", w);
    for (int pass = 0; pass < 2; pass++) {
        for (int d = 0; d < 7; d++)
            for (int k = 0; k < 4 && names[d][k]; k++)
                if (!strcmp(base, names[d][k])) {
                    if (plural)
                        *plural = pass;
                    return d;
                }
        if (n < 2 || base[n - 1] != 's')
            break;
        base[n - 1] = '\0'; /* "mondays" */
    }
    return -1;
}

static int nl_month(const char *w) {
    static const char *const m[12] = { "jan", "feb", "mar", "apr",
                                       "may", "jun", "jul", "aug",
                                       "sep", "oct", "nov", "dec" };
    static const char *const full[12] = {
        "january", "february", "march",     "april",   "may",      "june",
        "july",    "august",   "september", "october", "november", "december"
    };
    for (int i = 0; i < 12; i++)
        if (!strcmp(w, m[i]) || !strcmp(w, full[i]) ||
            (i == 8 && !strcmp(w, "sept")))
            return i;
    return -1;
}

/* "3", "3rd", "21st" -> day of month, else 0. */
static int nl_mday(const char *w) {
    char *end;
    long v = strtol(w, &end, 10);
    if (end == w || v < 1 || v > 31)
        return 0;
    if (*end && strcmp(end, "st") && strcmp(end, "nd") && strcmp(end, "rd") &&
        strcmp(end, "th"))
        return 0;
    return (int)v;
}

/* Minutes per unit word ("min", "hours", "d"...), 0 if not a unit. */
static int nl_unit(const char *w) {
    static const char *const mins[] = { "m", "min", "mins", "minute",
                                        "minutes", NULL };
    static const char *const hours[] = { "h", "hr", "hrs", "hour", "hours",
                                         NULL };
    static const char *const days[] = { "d", "day", "days", NULL };
    static const char *const weeks[] = { "w", "wk", "wks", "week", "weeks",
                                         NULL };
    if (nl_is(w, mins))
        return 1;
    if (nl_is(w, hours))
        return 60;
    if (nl_is(w, days))
        return 1440;
    if (nl_is(w, weeks))
        return 10080;
    return 0;
}

/* Clock time: "9", "9am", "9:30", "9.30pm", "21:00", with an optional
 * separate "am"/"pm" in `next`. need_marker: a bare "9" only counts after
 * "at". Returns tokens consumed (1 or 2), 0 if not a time. */
static int nl_clock(const char *w, const char *next, int need_marker, int *h,
                    int *m) {
    int hh = 0, mm = 0, digits = 0, have_colon = 0, ampm = 0, used = 1;
    const char *p = w;
    if (!strcmp(w, "noon") || !strcmp(w, "midday")) {
        *h = 12;
        *m = 0;
        return 1;
    }
    if (!strcmp(w, "midnight")) {
        *h = 0;
        *m = 0;
        return 1;
    }
    while (isdigit((unsigned char)*p) && digits < 2) {
        hh = hh * 10 + (*p++ - '0');
        digits++;
    }
    if (!digits)
        return 0;
    if (*p == ':' || *p == '.') {
        p++;
        if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1]))
            return 0;
        mm = (p[0] - '0') * 10 + (p[1] - '0');
        p += 2;
        have_colon = 1;
    }
    if (!strcmp(p, "am") || !strcmp(p, "a") || !strcmp(p, "a.m"))
        ampm = 1;
    else if (!strcmp(p, "pm") || !strcmp(p, "p") || !strcmp(p, "p.m"))
        ampm = 2;
    else if (*p)
        return 0;
    if (!ampm && next) {
        if (!strcmp(next, "am") || !strcmp(next, "a.m")) {
            ampm = 1;
            used = 2;
        } else if (!strcmp(next, "pm") || !strcmp(next, "p.m")) {
            ampm = 2;
            used = 2;
        }
    }
    if (!ampm && !have_colon && need_marker)
        return 0;
    if (mm > 59)
        return 0;
    if (ampm) {
        if (hh < 1 || hh > 12)
            return 0;
        if (ampm == 1 && hh == 12)
            hh = 0;
        else if (ampm == 2 && hh != 12)
            hh += 12;
    } else if (hh > 23) {
        return 0;
    }
    *h = hh;
    *m = mm;
    return used;
}

static void nl_fmt_date(char out[WA_REM_DATE_LEN + 1], int y, int m, int d) {
    char b[48];
    snprintf(b, sizeof(b), "%04d-%02d-%02d", y, m, d);
    snprintf(out, WA_REM_DATE_LEN + 1, "%.10s", b);
}

/* Wall date of `base` (in tz) plus `days`, as YYYY-MM-DD. */
static void nl_date_plus(int tz_min, time_t base, int days,
                         char out[WA_REM_DATE_LEN + 1]) {
    struct tm w;
    time_t t;
    wall_tm(tz_min, base, &w);
    w.tm_mday += days;
    w.tm_hour = 12; /* keep away from day edges while normalizing */
    w.tm_isdst = 0;
    t = timegm(&w);
    gmtime_r(&t, &w);
    nl_fmt_date(out, w.tm_year + 1900, w.tm_mon + 1, w.tm_mday);
}

static int nl_set_err(char *err, size_t cap, const char *msg) {
    if (err && cap)
        snprintf(err, cap, "%s", msg);
    return -1;
}

int wa_rem_is_request(const char *text) {
    char w[16];
    size_t k = 0;
    if (!text)
        return 0;
    while (*text == ' ' || *text == '\t' || *text == '\n')
        text++;
    if (*text == '/')
        text++;
    while (*text && !isspace((unsigned char)*text) && *text != ':' &&
           *text != ',' && k + 1 < sizeof(w))
        w[k++] = (char)tolower((unsigned char)*text++);
    w[k] = '\0';
    return !strcmp(w, "remind") || !strcmp(w, "reminder") ||
           !strcmp(w, "remindme");
}

/* Whole day names only: "sat", "saturday", "mon,wed", "mon-fri". */
static unsigned nl_days(const char *w) {
    char tmp[48];
    if (!*w)
        return 0;
    snprintf(tmp, sizeof(tmp), "%s", w);
    for (char *d = strtok(tmp, ",-"); d; d = strtok(NULL, ",-"))
        if (nl_weekday(d, NULL) < 0)
            return 0;
    return wa_rem_days_parse(w);
}

/* "20 minutes" / "2h" / "1h30m" at token i. Returns tokens used, 0 if none. */
static int nl_delay(const nl_toks_t *t, int i, long *minutes) {
    const char *a = nl_at(t, i);
    char *p;
    long v = strtol(a, &p, 10), sum = 0;
    int u;
    if (p == a || v <= 0 || v > 500000)
        return 0;
    if (!*p) {
        u = nl_unit(nl_at(t, i + 1));
        *minutes = v * u;
        return u ? 2 : 0;
    }
    for (;;) {
        char unit[8];
        size_t k = 0;
        while (isalpha((unsigned char)*p) && k + 1 < sizeof(unit))
            unit[k++] = *p++;
        unit[k] = '\0';
        if (!(u = nl_unit(unit)))
            return 0;
        sum += v * u;
        if (!*p)
            break;
        a = p;
        v = strtol(a, &p, 10);
        if (p == a || v <= 0 || v > 500000)
            return 0;
    }
    *minutes = sum;
    return 1;
}

/* Parses the WHEN part at *ip. Returns 0 or an error via nl_set_err. */
static int nl_when(const nl_toks_t *t, int *ip, time_t now, int tz_min,
                   wa_rem_spec_t *out, int *every, unsigned *mask,
                   int *day_off, int *weekday, char *err, size_t errcap) {
    int i = *ip, d, plural = 0;
    const char *w = nl_at(t, i);

    if (!strcmp(w, "daily") || !strcmp(w, "everyday")) {
        *every = 1;
        i++;
    } else if (!strcmp(w, "weekdays")) {
        *every = 2;
        *mask = 0x3E;
        i++;
    } else if (!strcmp(w, "weekends")) {
        *every = 2;
        *mask = 0x41;
        i++;
    } else if (!strcmp(w, "every") || !strcmp(w, "each")) {
        const char *a = nl_at(t, i + 1);
        i += 2;
        if (!strcmp(a, "day")) {
            *every = 1;
        } else if (!strcmp(a, "weekday") || !strcmp(a, "weekdays")) {
            *every = 2;
            *mask = 0x3E;
        } else if (!strcmp(a, "weekend") || !strcmp(a, "weekends")) {
            *every = 2;
            *mask = 0x41;
        } else if ((*mask = nl_days(a)) != 0) {
            *every = 2;
            for (;;) { /* "mon, wed and fri" */
                const char *x = nl_at(t, i);
                unsigned more;
                if (!strcmp(x, "and") || !strcmp(x, "&") || !strcmp(x, "+")) {
                    if (!(more = nl_days(nl_at(t, i + 1))))
                        break;
                    i += 2;
                } else if ((more = nl_days(x)) != 0) {
                    i++;
                } else {
                    break;
                }
                *mask |= more;
            }
        } else {
            return nl_set_err(err, errcap,
                              "after \"every\" use day, weekday, weekend or "
                              "day names like sat or mon,wed");
        }
    } else if (!strcmp(w, "today")) {
        *day_off = 0;
        i++;
    } else if (!strcmp(w, "tomorrow") || !strcmp(w, "tmrw")) {
        *day_off = 1;
        i++;
    } else if ((d = nl_weekday(w, &plural)) >= 0) {
        if (plural) { /* "saturdays" */
            *every = 2;
            *mask = 1u << d;
        } else {
            *weekday = d;
        }
        i++;
    } else if (wa_rem_date_parse(w, out->date) == 0) {
        i++;
    } else {
        int mon = nl_month(w), mday = nl_mday(nl_at(t, i + 1));
        if (mon < 0 || !mday) {
            mday = nl_mday(w);
            mon = nl_month(nl_at(t, i + 1));
        }
        if (mon < 0 || !mday)
            return nl_set_err(err, errcap,
                              "I need a day first: every day, every sat, "
                              "tomorrow, 2026-11-03 or nov 3");
        {
            struct tm n;
            int year;
            wall_tm(tz_min, now, &n);
            year = n.tm_year + 1900;
            if (mon < n.tm_mon || (mon == n.tm_mon && mday < n.tm_mday))
                year++;
            nl_fmt_date(out->date, year, mon + 1, mday);
            if (wa_rem_date_parse(out->date, out->date))
                return nl_set_err(err, errcap, "that date does not exist");
        }
        i += 2;
    }
    *ip = i;
    return 0;
}

int wa_rem_parse_request(const char *text, time_t now, int tz_min,
                         const char *to, wa_rem_spec_t *out, char *err,
                         size_t errcap) {
    char buf[1024];
    nl_toks_t t;
    int i, used = 0, every = 0, day_off = -1, weekday = -1;
    long delay = 0;
    unsigned mask = 0;
    struct tm w;

    if (!text || !out || !wa_rem_is_request(text))
        return nl_set_err(err, errcap, "not a reminder request");
    memset(out, 0, sizeof(*out));
    out->tz_min = tz_min;
    snprintf(buf, sizeof(buf), "%s", text);
    nl_tokenize(buf, &t);

    i = 1; /* trigger word */
    if (!strcmp(nl_at(&t, i), "me") || !strcmp(nl_at(&t, i), "us"))
        i++;

    if (!strcmp(nl_at(&t, i), "in")) {
        used = nl_delay(&t, i + 1, &delay);
        if (!used)
            return nl_set_err(err, errcap,
                              "use a delay like: in 20 minutes, in 2 hours, "
                              "in 1h30m");
        i += 1 + used;
    } else {
        if (nl_when(&t, &i, now, tz_min, out, &every, &mask, &day_off,
                    &weekday, err, errcap))
            return -1;
        if (!strcmp(nl_at(&t, i), "at"))
            i++;
        used = nl_clock(nl_at(&t, i), nl_at(&t, i + 1), 1, &out->hour,
                        &out->min);
        if (!used)
            return nl_set_err(err, errcap,
                              "I need a time after the day, like 13:00 or "
                              "1pm");
        i += used;
    }

    /* Everything after the schedule is the text, exactly as typed. Only
     * whitespace runs collapse, because the store is one line per reminder. */
    if (i < t.n) {
        const char *p = text + (t.orig[i] - buf);
        size_t off = 0;
        for (; *p && off + 1 < sizeof(out->text); p++) {
            if (isspace((unsigned char)*p)) {
                if (off && out->text[off - 1] != ' ')
                    out->text[off++] = ' ';
            } else {
                out->text[off++] = *p;
            }
        }
        while (off && out->text[off - 1] == ' ')
            off--;
        out->text[off] = '\0';
    }
    if (!out->text[0])
        return nl_set_err(err, errcap, "the reminder text is missing");
    if (to)
        snprintf(out->to, sizeof(out->to), "%s", to);

    if (delay) {
        time_t at = now + (time_t)delay * 60;
        at = ((at + 59) / 60) * 60; /* never early */
        wall_tm(tz_min, at, &w);
        out->hour = w.tm_hour;
        out->min = w.tm_min;
        nl_fmt_date(out->date, w.tm_year + 1900, w.tm_mon + 1, w.tm_mday);
        out->repeat = WA_REM_ONCE;
        return 0;
    }
    if (every == 1) {
        out->repeat = WA_REM_DAILY;
        return 0;
    }
    if (every == 2) {
        out->repeat = WA_REM_WEEKLY;
        out->days = mask;
        return 0;
    }

    out->repeat = WA_REM_ONCE;
    wall_tm(tz_min, now, &w);
    {
        int now_min = w.tm_hour * 60 + w.tm_min;
        int at_min = out->hour * 60 + out->min;
        if (out->date[0]) {
            char today[WA_REM_DATE_LEN + 1];
            nl_date_plus(tz_min, now, 0, today);
            if (strcmp(out->date, today) < 0 ||
                (!strcmp(out->date, today) && at_min <= now_min))
                return nl_set_err(err, errcap, "that time is in the past");
            return 0;
        }
        if (weekday >= 0) {
            day_off = (weekday - w.tm_wday + 7) % 7;
            if (day_off == 0 && at_min <= now_min)
                day_off = 7;
        } else if (day_off == 0 && at_min <= now_min) {
            return nl_set_err(err, errcap,
                              "that time already passed today");
        }
        nl_date_plus(tz_min, now, day_off, out->date);
    }
    return 0;
}

/* Friendly schedule: "tomorrow (Fri 31 Oct) at 09:00 UTC-6". */
void wa_rem_describe(const wa_reminder_t *r, time_t now, char *out,
                     size_t cap) {
    static const char *const MON[] = { "Jan", "Feb", "Mar", "Apr",
                                       "May", "Jun", "Jul", "Aug",
                                       "Sep", "Oct", "Nov", "Dec" };
    char tz[16], when[96];
    int off;
    if (!r || !out || !cap)
        return;
    off = r->tz_min;
    if (off == 0)
        snprintf(tz, sizeof(tz), "UTC");
    else if (off % 60)
        snprintf(tz, sizeof(tz), "UTC%c%d:%02d", off < 0 ? '-' : '+',
                 abs(off) / 60, abs(off) % 60);
    else
        snprintf(tz, sizeof(tz), "UTC%c%d", off < 0 ? '-' : '+', abs(off) / 60);
    if (r->repeat == WA_REM_ONCE && r->date[0]) {
        char today[WA_REM_DATE_LEN + 1], tmrw[WA_REM_DATE_LEN + 1];
        int y, mo, d, wd = date_weekday(r->date);
        nl_date_plus(r->tz_min, now, 0, today);
        nl_date_plus(r->tz_min, now, 1, tmrw);
        if (sscanf(r->date, "%d-%d-%d", &y, &mo, &d) != 3 || mo < 1 || mo > 12)
            snprintf(when, sizeof(when), "%s", r->date);
        else if (!strcmp(r->date, today))
            snprintf(when, sizeof(when), "today");
        else if (!strcmp(r->date, tmrw))
            snprintf(when, sizeof(when), "tomorrow (%s %d %s)",
                     wd >= 0 ? DNAMES[wd] : "?", d, MON[mo - 1]);
        else
            snprintf(when, sizeof(when), "%s %d %s %d",
                     wd >= 0 ? DNAMES[wd] : "?", d, MON[mo - 1], y);
    } else if (r->repeat == WA_REM_ONCE) {
        snprintf(when, sizeof(when), "next");
    } else if (r->repeat == WA_REM_DAILY || r->days == 0x7F) {
        snprintf(when, sizeof(when), "every day");
    } else if (r->days == 0x3E) {
        snprintf(when, sizeof(when), "every weekday");
    } else if (r->days == 0x41) {
        snprintf(when, sizeof(when), "every weekend");
    } else {
        char days[64];
        wa_rem_days_format(r->days, days);
        snprintf(when, sizeof(when), "every %s", days);
    }
    snprintf(out, cap, "%s at %02d:%02d %s", when, r->hour, r->min, tz);
    if (r->repeat != WA_REM_ONCE && r->date[0]) {
        size_t n = strlen(out);
        snprintf(out + n, cap - n, " from %s", r->date);
    }
}
