/* wa_remind.c — text-file reminder store (see wa_remind.h). */
#define _POSIX_C_SOURCE 200809L

#include "wa_remind.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *DNAMES[] = { "Sun", "Mon", "Tue", "Wed",
                                "Thu", "Fri", "Sat" };

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

static void rem_path(const char *auth_dir, char out[512]) {
    snprintf(out, 512, "%s/reminders.tsv", auth_dir ? auth_dir : "auth_info");
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
        char days[64], hm[16];
        char *p1, *p2, *p3, *p4;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (!n || line[0] == '#')
            continue;
        /* id\tdays\thh:mm\tto\ttext */
        p1 = strchr(line, '\t');
        if (!p1)
            continue;
        *p1++ = '\0';
        p2 = strchr(p1, '\t');
        if (!p2)
            continue;
        *p2++ = '\0';
        p3 = strchr(p2, '\t');
        if (!p3)
            continue;
        *p3++ = '\0';
        p4 = strchr(p3, '\t');
        if (!p4)
            continue;
        *p4++ = '\0';
        r.id = atoi(line);
        snprintf(days, sizeof(days), "%s", p1);
        snprintf(hm, sizeof(hm), "%s", p2);
        r.days = wa_rem_days_parse(days);
        if (!r.days && strcmp(days, "*"))
            continue;
        if (wa_rem_time_parse(hm, &r.hour, &r.min))
            continue;
        snprintf(r.to, sizeof(r.to), "%s", p3);
        snprintf(r.text, sizeof(r.text), "%s", p4);
        if (cnt < cap)
            out[cnt++] = r;
    }
    free(line);
    fclose(f);
    return cnt;
}

int wa_rem_add(const char *auth_dir, unsigned days, int hour, int min,
               const char *to, const char *text) {
    char path[512];
    wa_reminder_t cur[WA_REM_MAX];
    int n, nid = 1;
    FILE *f;
    if (!days || !to || !to[0] || !text || !text[0])
        return -1;
    if (hour < 0 || hour > 23 || min < 0 || min > 59)
        return -1;
    n = wa_rem_load(auth_dir, cur, WA_REM_MAX);
    for (int i = 0; i < n; i++)
        if (cur[i].id >= nid)
            nid = cur[i].id + 1;
    rem_path(auth_dir, path);
    f = fopen(path, "a");
    if (!f)
        return -1;
    {
        char ds[64];
        wa_rem_days_format(days, ds);
        fprintf(f, "%d\t%s\t%02d:%02d\t%s\t%s\n", nid, ds, hour, min, to,
                text);
    }
    fclose(f);
    return nid;
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
        wa_rem_days_format(cur[i].days, ds);
        fprintf(f, "%d\t%s\t%02d:%02d\t%s\t%s\n", cur[i].id, ds,
                cur[i].hour, cur[i].min, cur[i].to, cur[i].text);
    }
    fclose(f);
    rename(tmp, path);
    return 0;
}

int wa_rem_due(const wa_reminder_t *r, time_t now) {
    struct tm lt;
    if (!r)
        return 0;
    localtime_r(&now, &lt);
    if (!(r->days & (1u << lt.tm_wday)))
        return 0;
    return lt.tm_hour == r->hour && lt.tm_min == r->min;
}

/* tok helper: split on spaces, honoring simple quotes is overkill — keep it
 * simple and predictable for a tiny binary. */
int wa_rem_parse_cmd(const char *body, const char *default_to,
                     unsigned *days, int *hour, int *min,
                     char to_out[WA_REM_TO_MAX],
                     char text_out[WA_REM_TEXT_MAX]) {
    char tmp[768];
    char *toks[64];
    int nt = 0;
    int ti = 0;
    if (!body || !days || !hour || !min || !to_out || !text_out)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s", body);
    /* strip leading "/reminder" */
    {
        const char *p = tmp;
        if (!strncmp(p, "/reminder", 9))
            p += 9;
        memmove(tmp, p, strlen(p) + 1);
    }
    for (char *t = strtok(tmp, " \t"); t && nt < 64; t = strtok(NULL, " \t"))
        toks[nt++] = t;
    if (nt < 2)
        return -1;
    /* optional days */
    {
        unsigned m = wa_rem_days_parse(toks[ti]);
        if (m) {
            *days = m;
            ti++;
            if (ti >= nt)
                return -1;
        } else {
            *days = wa_rem_days_parse("Mon-Fri");
        }
    }
    /* HH:MM */
    if (wa_rem_time_parse(toks[ti], hour, min))
        return -1;
    ti++;
    if (ti >= nt)
        return -1;
    /* optional to (digits/+ or JID) */
    {
        const char *t = toks[ti];
        int is_to = strchr(t, '@') != NULL;
        if (!is_to) {
            int digits = 1;
            for (const char *p = t; *p; p++) {
                if (*p == '+' && p == t)
                    continue;
                if (*p < '0' || *p > '9') {
                    digits = 0;
                    break;
                }
            }
            if (digits && strlen(t) >= 7)
                is_to = 1;
        }
        if (is_to) {
            snprintf(to_out, WA_REM_TO_MAX, "%s", t);
            ti++;
            if (ti >= nt)
                return -1;
        } else if (default_to && default_to[0]) {
            snprintf(to_out, WA_REM_TO_MAX, "%s", default_to);
        } else {
            return -1;
        }
    }
    /* rest = text */
    text_out[0] = '\0';
    for (int i = ti; i < nt; i++) {
        if (i > ti)
            strcat(text_out, " ");
        strncat(text_out, toks[i], WA_REM_TEXT_MAX - strlen(text_out) - 1);
    }
    return text_out[0] ? 0 : -1;
}
