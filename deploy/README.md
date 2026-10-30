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

The daemon reloads `reminders.tsv` every 15 seconds
and also checks the previous minute, so a slow send does not make it miss its
slot.

`--timeout` is optional for `--daemon` and `--listen`; they run until stopped
by default. Use `--timeout SECS` only for a bounded test run.
