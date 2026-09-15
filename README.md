# 🛡️ Home-IDS

### Your network has a security guard now. One that never sleeps, never gossips about you to anyone, and gets sharper the longer it watches.

Home-IDS is a self-hosted network security system for people and small businesses who want real protection without a monthly bill, a cloud account, or a black box they're just supposed to trust. It watches every device on your network, tells the difference between "normal" and "something's wrong" *for your specific devices* — not a generic checklist — and steps in automatically when it's genuinely sure. When it's not sure, it asks you, in plain English, with a one-tap answer.

It's not a toy. It's been running against a real home network for months, catching real things, and it's brutally honest with itself about what it still can't do — you'll find that list further down, not buried.

---

## The problem it solves

Your smart TV, your kid's tablet, your work laptop, the smart plug you forgot you own — every one of them is a door. Most home and small-office networks have no idea what's actually happening on them: which device just got roped into a botnet, which "smart" gadget is quietly phoning data somewhere it shouldn't, which laptop just started scanning the rest of the network the way malware does right before it spreads.

Enterprise security teams have tools for this. Homes and small offices usually have nothing, or a $300 box that phones your traffic summary to a vendor's cloud and charges you every month to keep working.

**Home-IDS is what a security team would run for you, running on hardware you own, watching only your own network, answering only to you.**

---

## What it catches, and what it does about it

It watches for the real shapes threats actually take — data being smuggled out through DNS traffic, devices calling home to command-and-control servers, one infected device trying to spread to the rest of your network, malware fingerprints matched against live threat intelligence feeds, and — with an optional add-on — the same signature-matching technology serious network security appliances use for catching known exploits and malware outright.

When it's confident, it acts immediately and automatically, in the smallest way that actually solves the problem:

- **Block just the bad destination** — the malicious domain stops resolving, network-wide, instantly. The device keeps working normally otherwise.
- **Cut a misbehaving device off from the internet** — while it stays reachable on your own LAN, so you can still get to it and clean it up.
- **Quarantine it completely** — reserved for the strongest evidence, this fully isolates a device from everything until you release it.

Every action shows up on your phone the moment it happens, with a plain-English explanation of why, and a single tap to undo it if it's wrong.

---

## The part nobody else does: it grades its own work

Most alerting tools cry wolf constantly, and people learn to ignore them — which is exactly how the real alert gets missed. Home-IDS has a second system whose entire job is checking the first one's work before you ever see it:

- **It double-checks itself before bothering you.** A trained classifier and a semantic-similarity check run on every alert; if it's confident something's a false alarm, it quietly suppresses it and remembers the pattern so it doesn't happen again. If it's not sure, you still get told — clearly marked as low-confidence, never hidden and never oversold.
- **It learns each device individually.** Not "this is a smart speaker, speakers are chatty" — it learns *your* smart speaker's actual behavior, over time, and only from behavior it already independently judged safe, so a genuinely compromised device can't talk its way into a trusted history just by repeating itself.
- **One confirmed threat protects everything else instantly.** The moment it confirms something is genuinely malicious, every other device on your network is immediately protected from that exact threat too — no re-learning, no waiting.
- **It tunes itself, safely, without touching your settings.** When enough real evidence says a threshold is a little too twitchy for your network, it loosens it — never the other way around without your say-so — and every adjustment it makes is fully explained and instantly reversible.
- **It has an optional private AI analyst.** A local AI model — nothing sent to any outside service, ever — does a deeper review of what made it through, a few times a day, and can independently confirm false positives on its own. It's never taken at its word, either: a deterministic check sits between the AI's judgment and any action, and rejects it outright if it contradicts the hard evidence already on file, cites evidence irrelevant to what it's actually reviewing, or can't point to a destination this device already has a track record with.

The net effect: it gets quieter and more accurate the longer it runs, instead of noisier.

---

## Who this is for

**Prosumers** — you already run Pi-hole, you already care about your home network more than most, and you want the next step up without paying a SaaS company to watch your family's traffic.

**Small companies and small offices** — you don't have a security team, you can't justify an enterprise appliance and its subscription, but "we have no idea what's happening on our network" isn't an acceptable answer either. This gives you a real, always-on watchdog without adding headcount or a recurring line item.

---

## See it in action

A real alert isn't a wall of numbers — it's built to be understood in five seconds:

> **⚠️ HIGH — kitchen-laptop, auto-blocked**
> **What happened:** Contacted a suspicious domain over DNS. The domain name itself was structured like an encoding scheme — a common way malware smuggles data out past normal filters.
> **Why:** Two independent things agree: the domain matches a known malware-tracking blocklist, *and* the traffic pattern matches DNS tunneling.
> **How confident:**
> — Is this really the attack pattern? **91%** (two independent signals agree)
> — Could this still be a false alarm? **8%** (checked against every known-safe pattern — none matched)
>
> [🛡️ Mark False Positive]  [↩️ Undo Block]

That's it. What happened, why, how sure it is, and a one-tap way to correct it if it's wrong — no decoding required.

The self-tuning described in the next section sends its own plain-English notifications too — "I just decided this domain is safe, tap here if I'm wrong," "this device's history now protects every other device from the same threat." Real examples of every one of those, alongside exactly what happens in the background when you see them, are in [`Documentation/ARGUS_ARCHITECTURE.md` §5](Documentation/ARGUS_ARCHITECTURE.md#5-autotuning).

---

## You can watch it think, not just trust it

Every claim above is backed by a live dashboard, not a promise. Home-IDS ships with six pre-built dashboards and well over a hundred live metrics covering exactly what it's doing right now: what it's learned about your devices, what it's suppressed as noise and why, how its own settings have shifted from the defaults, and the live health of every piece it depends on. There's a dashboard built around one question specifically — *what did it learn, how did it tune itself, what did it quiet down, and what couldn't it do* — because a security tool you can't audit isn't one you should trust with your network.

---

## Why not just buy a commercial box?

Commercial home-network security appliances are real products that work. They also usually mean your traffic summary goes to someone else's cloud, you pay for it every month to keep working, and when it makes a call about your own network, you have no way to see why.

Home-IDS trades that for: **it's free, it's entirely yours, and nothing about your network ever leaves your house** — including its optional AI analyst, which runs locally instead of calling out to anyone. It runs comfortably on modest hardware you likely already own. That combination of always-on autonomous protection, full transparency into every decision, and genuine self-improvement over time is normally something you'd pay a real subscription for, if you could find it at all outside of expensive commercial or enterprise-grade gear.

**And here's the part most product pages leave out:** it's not psychic, it can't see inside an encrypted VPN tunnel (nothing legitimately can), and its deepest inspection is strongest for wired devices — WiFi coverage is real but currently more targeted than continuous on a typical all-in-one router. We'd rather tell you that up front than have you discover it later. The full, unvarnished, threat-by-threat account of exactly where it's strong and where it's still maturing lives in the [Architecture doc](Documentation/ARGUS_ARCHITECTURE.md) — written for the technically curious, not hidden from anyone.

---

## What it's built on

Three systems working together — a real-time watchdog that decides, a self-correcting judge that keeps it honest and quiet, and an optional local AI analyst for deeper review — all built on open, well-respected foundations (Pi-hole for DNS, Grafana for dashboards, and industry-standard network-monitoring and signature-detection tools underneath). If you want the actual architecture diagrams, the mathematics, and every design decision explained and justified, that's what the [Architecture doc](Documentation/ARGUS_ARCHITECTURE.md) is for.

---

## Getting started

| Document | For |
|---|---|
| [INSTALL.md](Documentation/INSTALL.md) | Setting it up for the first time — step by step, including everything it depends on. |
| [USER_MANUAL.md](Documentation/USER_MANUAL.md) | Running it day to day — every setting, every dashboard, what everything means. |
| [ARGUS_ARCHITECTURE.md](Documentation/ARGUS_ARCHITECTURE.md) | The technical deep-dive — architecture, scheduling, decision engines, autotuning, and every self-tuning feedback loop with real Telegram alert examples. |
| [ARGUS_DECISIONS.md](Documentation/ARGUS_DECISIONS.md) | Standing rules, notable closed decisions, and the roadmap of what's deliberately not built (yet). |
| [CHANGELOG.md](Documentation/CHANGELOG.md) | What's changed, release by release. |

New here? Start with [INSTALL.md](Documentation/INSTALL.md).
