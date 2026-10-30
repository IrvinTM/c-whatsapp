# Running c-whatsapp as a tiny reminder service

The daemon is a single-threaded, event-driven process. A `make tiny` build is
about **170 KB** stripped and idles at about **3.5 MB of private memory**
(~12 MB RSS including shared OpenSSL/libc pages), which fits a very small VM.

## 1. Build and install

```sh
make tiny
sudo install -Dm755 build/tiny/c-whatsapp /usr/local/bin/c-whatsapp
```

`make tiny` uses `-Os`, LTO, section GC and strips the result. The normal
`make` build keeps `-g` and is only for development.

## 2. Create the service user and state dir

```sh
sudo useradd --system --home-dir /var/lib/c-whatsapp \
    --shell /usr/sbin/nologin c-whatsapp
sudo install -d -o c-whatsapp -g c-whatsapp -m 700 /var/lib/c-whatsapp
```

All mutable state stays in `/var/lib/c-whatsapp`:

- `creds.json` — linked-device session
- `signal.tsv` — Double Ratchet sessions
- `prekeys.tsv` — one-time prekeys
- `reminders.tsv` — reminders (plain tab-separated text)

Back up that directory if you want to keep the session.

## 3. Link the WhatsApp account once

Use either a pairing code (no camera needed):

```sh
sudo -u c-whatsapp /usr/local/bin/c-whatsapp \
    --auth-dir /var/lib/c-whatsapp --pair 15551234567
```

or copy an existing linked `auth_info/` from a development machine:

```sh
sudo cp -a auth_info/. /var/lib/c-whatsapp/
sudo chown -R c-whatsapp:c-whatsapp /var/lib/c-whatsapp
```

If you used `--pair`, run the command a second time to log in with the saved
session. The daemon's reconnect loop handles the usual post-pairing restart.

## 4. Say who may set reminders

Chat commands are **off** until you name the allowed numbers. Messages from
anyone else are ignored (and logged).

```sh
sudo install -d -m 755 /etc/c-whatsapp
printf 'CWA_ALLOW=15551234567\n' | \
    sudo install -m 600 /dev/stdin /etc/c-whatsapp/env
```

`CWA_ALLOW` is comma-separated digits with country code.

## 5. Install and start the unit

```sh
sudo install -Dm644 deploy/c-whatsapp.service \
    /etc/systemd/system/c-whatsapp.service
sudo systemctl daemon-reload
sudo systemctl enable --now c-whatsapp
systemctl status c-whatsapp
journalctl -u c-whatsapp -f
```

The unit runs `--daemon --timeout 0`, restarts on failure, and caps the
process at 64 MB / 16 tasks. It needs no inbound ports.

## 6. Manage reminders

With the daemon running, add reminders from the same state dir:

```sh
sudo -u c-whatsapp /usr/local/bin/c-whatsapp \
    --auth-dir /var/lib/c-whatsapp \
    --remind-add '*' 09:00 15551234567 Morning check-in

sudo -u c-whatsapp /usr/local/bin/c-whatsapp \
    --auth-dir /var/lib/c-whatsapp --remind-list
```

From an allowed phone, message the bot account using this format:

```text
reminder <when> <time> <text>

reminder every day 08:00 take pills
reminder every sat 1pm class
reminder every mon,wed 18:30 gym
reminder every weekday 7:50am class
reminder tomorrow 09:00 call mom
reminder 2026-11-03 14:30 dentist
reminder nov 3 2pm dentist
reminder in 20 minutes check the oven
list
delete 3
help
```

All times are **UTC-6** (`WA_REM_TZ` in `include/wa_remind.h`), whatever the
server's clock says. Everything after the time is kept as typed, so pasted
text can contain dates and times safely; line breaks become spaces. A message
that doesn't fit the format is not saved, and the reply says why. Reminders
created in chat are delivered to the sender's number.

Repeating (nag) reminders are described in the next section. The daemon
reloads `reminders.tsv` every 15 seconds
and also checks the previous minute, so a slow send does not make it miss its
slot.

`--timeout` is optional for `--daemon` and `--listen`; they run until stopped
by default. Use `--timeout SECS` only for a bounded test run.

## 7. Repeating "nag" reminders

A nag is re-sent every interval until you settle it:

```text
reminder every <interval> [until done] <text>
reminder hourly <text>

reminder every hour take pills
reminder every 30 minutes stretch
reminder every 2 hours drink water
reminder every 1h30m until done check the oven
reminder hourly stand up
```

Intervals: `hour`, `half hour`, `30 minutes`, `2h`, `1h30m`, `90m`; from
15 minutes to 24 hours. `until done` is optional and changes nothing. No
clock time or date is accepted: a nag starts when you create it, and the
first message arrives one interval later (not immediately).

Settle a nag from the same chat with `done N`, `ok N`, `okay N` or `stop N`
(`N` is the reminder number from the confirmation, `#3` also works). A bare
`done` settles your only nag, or lists yours if you have several. `delete N`
works too. `done N` on a normal reminder is refused and points at `delete`.

Timing and limits:

- **Jitter.** Each gap is the interval plus or minus a random 0 to 5 minutes
  (never closer than 5 minutes to the previous message), so the messages are
  not robotically regular. The gap is computed from the scheduled time, so
  polling lag does not accumulate.
- **Caps.** At most 24 messages per nag; the 24th says it is the last
  reminder and the nag then removes itself. At most 5 nags are active; a new
  one is refused until you settle one.
- **Downtime.** If the daemon was down or offline when a message was due, it
  sends at most one catch-up message after it returns, then reschedules from
  that moment. A failed send is retried after 2 minutes.
- **Time zone.** Times shown are still UTC-6. There are no quiet hours: nags
  send around the clock.

Storage is `reminders.tsv` format version 3. A nag line adds three fields
after the text:

```text
id  date  HH:MM  tz  nag  -  to  text  interval_min  next_fire_epoch  sent
1   2026-10-30  10:15  -360  nag  -  15551234567@s.whatsapp.net  take pills  60  1793000000  0
```

`date` and `HH:MM` are the creation time; `next_fire_epoch` is the UTC time of
the next send and `sent` the number of messages so far. Fields are
tab-separated. Because the daemon and the CLI both rewrite this file, they
take an exclusive `flock` on `reminders.lock` next to `reminders.tsv`; leave
that file in place.

Downgrading: an older binary skips nag lines it does not understand, and its
`--remind-del` or chat `delete` rewrites the file without them, so nags would
be lost. Settle or note your nags before rolling back.
