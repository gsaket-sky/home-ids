# Home-IDS User Manual

How to use Home-IDS from day to day. No technical background is needed. Setting up the box is covered in the
installation guide; how the system works inside is in the
[Engineering Manual](https://github.com/gsaket-sky/home-ids/blob/main/Documentation/ENGINEERING_MANUAL.md).

## Contents

1. [What Home-IDS does for you](#1-what-home-ids-does-for-you)
2. [The first two weeks](#2-the-first-two-weeks)
3. [Opening the web page](#3-opening-the-web-page)
4. [Home: one status, one next step](#4-home-one-status-one-next-step)
5. [Devices](#5-devices)
6. [Alerts](#6-alerts)
7. [Insights](#7-insights)
8. [System](#8-system)
9. [Integrations](#9-integrations)
10. [Setup](#10-setup)
11. [Password](#11-password)
12. [Alerts on your phone (Telegram)](#12-alerts-on-your-phone-telegram)
13. [How much it does on its own](#13-how-much-it-does-on-its-own)
14. [What is on, and what you can add](#14-what-is-on-and-what-you-can-add)
15. [Looking after itself](#15-looking-after-itself)
16. [Privacy](#16-privacy)
17. [Updates, backups and moving to a new box](#17-updates-backups-and-moving-to-a-new-box)
18. [When something looks wrong](#18-when-something-looks-wrong)
19. [Questions and answers](#19-questions-and-answers)

---

## 1. What Home-IDS does for you

Home-IDS watches every device on your network, learns what is normal for each one, and notices when something
changes in a way that suggests trouble. It wants two independent signs before it raises a serious alarm. When it is
sure, it acts: it can block a dangerous website for every device, cut a device off the internet, or isolate it.
Every action is explained in plain words and can be undone with one click.

It looks after itself: it learns, adjusts, cleans up, updates and repairs itself. You do not need to do anything
day to day. Everything in this manual is optional help for when you want to look or step in.

## 2. The first two weeks

For the first **14 days** Home-IDS is in its **learning period**. It watches and alerts, but it does not block
anything automatically, so it can learn your network first. The home page shows **Learning your network** during this
time. If you are confident earlier, press **Turn on protection now** on the home page.

To help it learn faster:

- **Confirm device types.** On the Devices page, confirm or correct what each device is (phone, TV, printer and so
  on).
- **Tell it about false alarms.** If you use Telegram, press **Mark safe** on an alert about something you know is
  fine.
- **Point your router's DNS at the box**, if the installer has not already, so every device's lookups are seen and
  can be filtered.

## 3. Opening the web page

Open `http://<box-address>:8011` on a phone or computer on your network, and sign in with your password. The page
works on a phone, and follows your device's light or dark setting.

The menu has **Home**, **Devices**, **Alerts**, **Insights** and **System**. **Integrations**, **Setup**, **Password**
and the **Expert** tools are under **More** (or in the side menu on a wide screen).

## 4. Home: one status, one next step

The top of the home page always shows one of these:

| Status | Meaning |
|---|---|
| **Your network is protected** | No alerts in the last 24 hours, and everything is running |
| **Learning your network** | The learning period: alerts are on, automatic blocking starts later |
| **Protected, with a hiccup** | Protection works, but a part is running below par (shown by name) |
| **Needs your attention** | There were alerts in the last 24 hours |
| **Act now** | There was a critical alert in the last 24 hours |
| **Protection is limited** | A core part is down; see System |

Below it you see the next thing worth doing (or "Nothing to do"), the most recent alerts, and a short system summary.

## 5. Devices

The Devices page lists every device Home-IDS has seen, with its name, type and state. The filters at the top are
**All**, **Active**, **Needs a look**, **Isolated** and **Type guessed**.

- **Confirm** a guessed type with one tap, or pick the right type from the list. Your answer is remembered and
  applied straight away, and Home-IDS stops guessing for that device.
- **Block** cuts a device off the network until you release it.
- **Release** undoes a block or an automatic isolation. After a release, Home-IDS will not isolate that device again
  on its own for an hour, unless it sees something serious, such as the device attacking others.
- **Forget** (the bin icon) removes a device that has gone for good.

**Phones that change their address.** Modern phones use a "private Wi-Fi address" for privacy. Home-IDS still
recognises them as the same device, so you do not get a new entry every time.

## 6. Alerts

The Alerts page shows alerts from the last 24 hours, 7 days or 30 days, filtered by **Critical**, **High** or **Worth a
look**.

Each alert is a short story in plain words:

- which device;
- what was noticed;
- where it was going (by name, owner and country);
- the explanation Home-IDS believes;
- the harmless explanation it considered, and why that did not fit;
- what it did about it.

A device that is isolated has a **Release** button on the alert; any other device has **Block device**.

| Level | What it means |
|---|---|
| **Critical** | Strong, corroborated evidence, or a tripwire (such as the decoy) was touched. Usually acted on automatically |
| **High** | At least two independent signs agree. Websites may be blocked; isolating a device may ask for your approval |
| **Worth a look** | A single sign, or one that kept recurring. Watched, never acted on alone |

**If an alert is about something you know is fine:** release the device if it was isolated. With Telegram connected,
press **Mark safe** on the alert, so Home-IDS learns that this is normal for that device and does not raise it again.

## 7. Insights

The Insights page gives short, practical suggestions in plain words, such as devices waiting for a type, the learning
period ending, or a background task that has not run. Each one links to where you can act. When there is nothing to
do, it says so.

## 8. System

- **Parts:** every part of the system with its health, and a **Restart** button for each.
- **Background jobs:** the nightly and periodic tasks, when each last ran and whether it succeeded, with **Run now**.
- **Threat data:** how fresh each threat-intelligence source is.
- **Resources:** memory, disk and load.
- **Models:** the learning models and when they were last trained.
- **Maintenance tools:** one-click clean-ups, each with a **Preview** first:

| Tool | What it does |
|---|---|
| Tidy confirmed threats | Removes "confirmed threat" entries that should never have been recorded, such as public DNS servers and big cloud providers |
| Unblock harmless sites | Reviews blocked sites and releases the ones that do not look malicious |
| Merge duplicate devices | Joins a device that was recorded twice into one |
| Audit shared indicators | Finds threat indicators that many devices "hit" because of a past fault, not an attack |
| Clean training data | Marks old, mislabelled alert records so the learning skips them |

You rarely need this page, because Home-IDS restarts and repairs parts on its own (section 15).

## 9. Integrations

Every outside service Home-IDS can use, each with what it does, its terms, a **Test** button and **Save**. Keys are
stored on the box and never shown again after saving.

| Integration | What it adds | Needed? |
|---|---|---|
| **Pi-hole (DNS filter)** | Built in. Sees every device's lookups and applies website blocks | Included |
| **Fritz!Box router** | Device names, cutting a device off the internet at the router, and short Wi-Fi captures for deeper checks | Optional, recommended if you have one |
| **Telegram** | Alerts, approvals, "mark safe" and "release" on your phone | Optional, recommended |
| **Ollama (AI second opinion)** | A local AI model writes a plain-language second opinion on alerts. It is advisory only, and is checked against the evidence | Optional, needs your own Ollama server |
| **AlienVault OTX, abuse.ch (URLhaus, ThreatFox)** | Extra lists of known bad addresses, domains and links | Optional; free plans are for personal use only (see section 14) |
| **AbuseIPDB** | Crowd-sourced abuse reports for addresses | Optional; same licence note |
| **VirusTotal** | Antivirus-engine verdicts for destinations | Optional; same licence note |
| **MaxMind GeoLite2** | City-level location in alerts (country and owner are built in) | Optional, needs a free MaxMind key |

## 10. Setup

- **Threat data:** shows the built-in sources and when they last updated. You can add city-level location by
  downloading with a MaxMind key, or by uploading files you already have.
- **Router capture:** sets up and tests short Wi-Fi captures through a supported router. Once a router is
  configured, Home-IDS uses captures on its own when it needs a closer look, for example at a new device, a
  suspicious burst or an unclear identity. Captures stay within strict hourly and disk limits.
- **Pi-hole import:** imports a Pi-hole Teleporter backup, bringing your existing block lists and settings across.

## 11. Password

One password protects the web page, the expert console, the engine and Pi-hole (and Grafana, if you add it).
Change it here: enter the current one, enter the new one twice, and press **Change everywhere**. If any part refuses
the change, nothing is changed, so you are never left with two different passwords.

## 12. Alerts on your phone (Telegram)

Add a Telegram bot under Integrations (bot token and your chat ID), then press **Test**. You then receive:

- serious alerts, as the same plain-language story as the web page;
- buttons on each alert: **Approve block** (when approval is on), **Release** and **Mark safe**;
- notices when something is released, when a part has trouble and when it recovers, and findings from the nightly
  look-back over past traffic.

Commands: `/release <device>` or `/unblock <device>` releases one device; `/release_all` or `/unblock_all` releases
everything.

Repeated alerts about the same thing are grouped. You get a message when it starts, when it gets worse, and a "still
ongoing" update every 15 minutes, not one message per detection. To limit who may press the buttons in a group chat,
add the allowed chat IDs under Expert settings.

## 13. How much it does on its own

**It does on its own:**

- learns, tunes and cleans up;
- blocks dangerous websites for every device;
- contains a device that is attacking others or touched the decoy;
- restarts parts that fail, and updates itself with automatic rollback.

**It asks first (by default):** before isolating a device at the router, or cutting it off the network.

**It never does on its own:**

- act on a single weak sign;
- contain a device you marked as protected (router, NAS, this box);
- change your configuration file.

You can change this under Expert settings:

- **Make isolation automatic:** turn off "interactive blocking".
- **Alerts only, never block:** turn off "IPS enabled". The box then only detects.
- **Test without acting:** turn on "simulation mode". Actions are logged but not carried out.
- **Learning period length:** set "onboarding mode days".

## 14. What is on, and what you can add

Everything the licences allow is switched on from the start:

- the **decoy**: a fake, easy-looking computer on your network that nothing should ever touch, so any contact is a
  strong sign of an intruder;
- **deeper scans** of Wi-Fi captures, once a router is connected;
- every background job, including the **nightly look-back**, which re-checks past traffic against today's threat
  knowledge;
- **country rules**, which flag contact with a short list of countries and block only when a second sign agrees.

Some threat-intelligence services (AlienVault OTX, URLhaus, ThreatFox, AbuseIPDB, VirusTotal) are free only for
personal, non-commercial use, so they are off by default. If your use is personal, or you have a commercial licence
from each provider, switch them on under Integrations (or ask your installer to run
`scripts/enable-licensed-feeds.sh`) and add your keys.

**Dashboards** (Grafana) are an optional extra for people who like charts. They use a lot of memory on a small board,
so they are off by default.

## 15. Looking after itself

- **The disk cannot fill up.** Old data is removed on a schedule, and a nightly disk check keeps the total under a
  fixed limit.
- **Memory cannot creep up.** Every part has a hard memory limit. If one part misbehaves, only that part is restarted.
- **It repairs itself.** A built-in health check looks at every part every 15 seconds and restarts anything that stops
  working, waiting longer between attempts each time. If memory gets tight, it switches off non-essential extras until
  things calm down, then switches them back on.
- **It survives power cuts.** Its records are written safely, so a sudden power loss does not lose anything already
  saved. When the power returns, it carries on where it was, with everything it had learned.
- **It is gentle on SD cards.** It writes as little as possible and keeps short-lived data in memory.
- **It keeps learning.** Each device's normal behaviour and the alarm thresholds keep improving, in small, tested,
  reversible steps.

### Seeing what it has learned

The expert console's **Autonomy** tab shows what Home-IDS has learned and changed by itself. You never need to act
on it.

- **Tunable parameters** are the 16 sensitivity settings Home-IDS may adjust within fixed limits, such as how many
  devices a gadget must probe before it counts as scanning the network, or how long a website you confirmed as safe
  stays trusted. **Tuned** means it has moved one away from its starting value, based on evidence from your network.
- **Autotuner history** lists each change, whether it made the system more careful (**tightened**) or more relaxed
  (**loosened**), and whether it is still on trial, in force, or undone.
- **Still building**, with percentages, shows harmless patterns the system is learning to stop alerting about. Each
  row is one device and one kind of alert. Every time such an alert turns out to be harmless (you mark it safe, or
  the system concludes so itself) the bar grows, and it slowly shrinks again if nothing confirms it. Once **two
  different kinds of evidence** for the same pattern reach 100%, Home-IDS stops notifying you about it for that
  device. That takes about five confirmations in a row. It still records it, and anything genuinely dangerous is
  always reported.

## 16. Privacy

Everything stays on the box in your home. There is no account and no cloud. Home-IDS reads the "envelope" of network
traffic (who talks to whom, when, how much, and which names are looked up), not the contents of your messages or
pages. Its only outside contacts are:

- threat-intelligence downloads;
- the optional services you switch on;
- Telegram, if you add it;
- signed update checks.

Update checks use a per-device token and send nothing about your network.

## 17. Updates, backups and moving to a new box

- **Updates** install themselves in a night-time window. Each one is digitally signed and checked before it is used.
  If the new version does not come up healthy within two minutes, the box goes back to the previous version by
  itself.
- **Backup:** stop the system and copy the `docker/data` and `docker/config/ids` folders. Restoring is the reverse.
- **New box:** restore the backup on the new box. Devices, history, learned behaviour and your settings all come with
  it.

## 18. When something looks wrong

| You see | Try |
|---|---|
| A device you know is blocked by mistake | Devices → **Release**; with Telegram, also press **Mark safe** on its alert so it learns |
| A website you need is blocked | System → **Unblock harmless sites** (preview first) |
| "Protection is limited" | System → find the part shown in red → **Restart** |
| "Protected, with a hiccup" | System shows which part; it usually recovers on its own within minutes |
| A device appears twice | System → **Merge duplicate devices** (preview first) |
| No devices appear | Make sure the box is connected where it can see your traffic, and that the router uses the box for DNS |
| The page is slow right after a restart | Wait a minute while it warms its caches |
| Telegram is silent | Integrations → Telegram → **Test** |
| A threat source shows as old | System → Threat data. The box keeps using its last good copy and retries on its own |

## 19. Questions and answers

**Will it slow down my internet?** No. Home-IDS watches a copy of the traffic, so it does not sit in the path of
your connection. DNS filtering is as fast as a normal home resolver.

**Can it see what I type or read?** No. It sees connection details and the names that are looked up, not content.

**What if it blocks something important?** The router, a NAS and the box itself are protected from automatic action.
Any block can be undone with one click, and a released device is left alone afterwards unless it does something
serious.

**Do I need to update threat lists or tune settings?** No. Both happen automatically.

**What happens if the internet goes down?** It keeps watching and deciding with what it already knows, and the status
page tells you that its outside sources cannot be reached.

**Is it a guarantee against all attacks?** No security product can promise that. Home-IDS is built to make problems
visible early and to act carefully when it is sure.
