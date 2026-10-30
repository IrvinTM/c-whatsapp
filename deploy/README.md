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
printf 'CWA_ALLOW=15551234567\nCWA_TZ=UTC-6\n' | \
    sudo install -m 600 /dev/stdin /etc/c-whatsapp/env
```

`CWA_ALLOW` is comma-separated digits with country code. `CWA_TZ` is the
default timezone for chat requests (a fixed offset; send `tz UTC-5` from the
phone to change it later, e.g. for daylight saving).

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

From an allowed phone, just message the bot account in plain words:

```text
remind me in 20 minutes to check the oven
remind me tomorrow at 9am to call mom
remind me friday evening to pay rent
remind me nov 3 at 14:30 dentist
remind me every weekday at 7:50 class starts
remind me every mon and wed at 6pm gym
list
delete 3
tz UTC-6
help
```

The daemon replies with exactly what it understood ("Reminder #4 set for
tomorrow (Sat 31 Oct) at 09:00 UTC-6"), so a misread time is easy to spot
and `delete` it. The older `/reminder 07:50 Mon-Fri text` form is understood
too. Reminders created in chat are delivered to the sender's number.

The daemon reloads `reminders.tsv` every 15 seconds
and also checks the previous minute, so a slow send does not make it miss its
slot.

`--timeout` is optional for `--daemon` and `--listen`; they run until stopped
by default. Use `--timeout SECS` only for a bounded test run.
