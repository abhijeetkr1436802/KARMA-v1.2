# KARMA Presentation Speaker Guide

How to present each of the 25 slides in `presentation/index.html`: what is on screen, what to say and what to click.

## Before you start

The deck has 25 slides and runs 18–22 minutes; aim for 20, then questions. Open `presentation\index.html` in Chrome or Edge and press **F** for full screen. **→**, **Space** or a clicker moves forward; **←** goes back.

- **Build slides:** slides 3, 4, 8, 9, 14, 15, 16, 18 and 19 reveal step by step. Keep pressing → until the slide is complete before moving on.
- **Live slide 13:** click the command line to type. Press **Esc** before pressing Space, or Space types a space instead of moving on.
- **KARMA running:** start the server and press **Reset System** before you begin, so the live demo starts clean.
- **Split between speakers (suggested):** Part 1 one speaker, Part 2 the second, Part 3 the lead with the live demo, Part 4 the fourth. Hand over with one sentence that links the parts.

| Part | Slides | Time | Goal |
| --- | --- | --- | --- |
| 1. The problem | 1–7 | 4 min | Make the examiner feel the risk |
| 2. The idea | 8–13 | 5 min | Show how a honeypot catches attackers |
| 3. KARMA inside | 14–19 | 6 min | The demo story and how it is built |
| 4. Proof and future | 20–25 | 5 min | Security, tests, limits, conclusion |

## Part 1 — The problem (slides 1–7, about 4 minutes)

Goal: by slide 7 the examiner should agree that walls are not enough and traps are needed.

| # | Slide | On screen | What to say | Do |
| --- | --- | --- | --- | --- |
| 1 | Cold open | A terminal types an SSH login, `whoami`, `cat /etc/passwd`; then "Someone just broke in." | Stay silent while it types. Then: "Someone just broke in. Not into our server — into our trap." | Wait for the typing to finish |
| 2 | Cover | "The attack returns." with the live map video; project name and college | "We are Team KARMA. KARMA is a honeypot platform: it lures attackers into fake servers, reads every move and locks them out." | Introduce the team in one line |
| 3 | Breached since 2024 | Five company names light up one by one with real headlines: Salesforce, Coupang, Co-op, JLR, Canvas | One line per press: "1 billion records claimed from Salesforce customers…" End: "These companies had firewalls." | Press → five times |
| 4 | And here in India | Star Health, Tata Technologies, CERT-In 29.44 lakh incidents | "This is not somewhere else. 31 million Star Health policyholders' records were posted online. CERT-In handled 29.44 lakh incidents in 2025." | Press → three times |
| 5 | 241 days | A grid fills with 241 red squares | "On average an intruder is inside for 241 days before anyone notices. Each square is a day they walk around unseen. Average cost: $4.44 million (IBM 2025)." | Let the counter reach 241 |
| 6 | Attackers bring keys | 22% stolen credentials, 44% ransomware, 30% third parties | "A firewall checks the door. But 22% of breaches start with a valid stolen password — the firewall waves it through." | Point at 22% |
| 7 | Stop building walls. Lay traps. | Firewall vs honeypot comparison | "A honeypot is a decoy that looks more valuable than the real server. Nobody has a reason to touch it, so anyone who does is an intruder — almost no false positives." | Hand over to Part 2 |

**Handover line:** "So how does a trap actually catch someone? …"

## Part 2 — The idea (slides 8–13, about 5 minutes)

Goal: explain the honeypot loop once, clearly, then let the examiner try it on slide 13.

| # | Slide | On screen | What to say | Do |
| --- | --- | --- | --- | --- |
| 8 | Lure → Trap → Profile → Contain | A diagram: the attacker aims at the real server, the path bends into the KARMA decoy, a tag shows T1059 risk 90, then BLOCKED | Lure: "KARMA runs fake services that look real." Trap: "The attacker reaches the decoy first; the real server is never touched." Profile: "Every command is logged, mapped to MITRE ATT&CK and scored 0–100." Contain: "Cross 75 and KARMA quarantines them." | Press → three times (or drag the slider) |
| 9 | KARMA | The word KARMA opens into its letters | "In security, karma is an attack that comes back to its sender. KARMA turns your own network into the trap." | Press → once to open the letters |
| 10 | Objectives | Five numbered goals: Lure, Record, Classify, Contain, Explain; out-of-scope line | Read the five bold words, one sentence each. Mention scope: "We did not aim to guard a real production network or use machine learning." | — |
| 11 | Others do one part | Table: firewall, Cowrie, T-Pot, Wazuh vs KARMA | "Cowrie only logs. T-Pot needs a Linux server running Docker. Wazuh has no decoys. KARMA does the whole loop on one laptop." | Point at the amber KARMA row |
| 12 | Live attack map | Real recording of the visualizer | "This is a real recording. Every attack starts on course for production; the honeypot pulls it in." | Let the video play 5–10 seconds |
| 13 | Type what an attacker types | A command line, what the attacker sees, and KARMA's verdict | "Try it." Type or click `whoami` (T1059, risk 90, quarantines), then `ls -la` (logged only), then `' OR 1=1 --` (T1190 SQL injection). "These are the same rules KARMA's engine uses." | Click the line to type; **Esc** before moving on |

**Handover line:** "Now let's watch a full attack from start to finish."

## Part 3 — KARMA inside (slides 14–19, about 6 minutes)

Goal: tell one attack story, show the real screens, then explain how one keystroke flows through the system. If you run the live demo, do it right after slide 14.

| # | Slide | On screen | What to say | Do |
| --- | --- | --- | --- | --- |
| 14 | Steal the keys. Trip the alarm. | Six stages: Recon, Web recon, Break-in, Loot, Use the key, Contained | One sentence per press, as shown under the cards. End with: "In Contain mode only high-risk acts block; Observe mode never blocks, so we can rehearse." | Press → five times; then switch to the live demo if planned |
| — | Live demo (optional, 3 min) | Attacker laptop + KARMA dashboard | Run the attack script from the Decoys and Attacks Guide. On the dashboard open **▶ Replay** and **📄 Report** for the attacker | Press **Reset System** before; return with the slide tab |
| 15 | One console for the whole hunt | Real screenshots: dashboard, MITRE heatmap, honeytoken vault | Dashboard: "Every probe appears the second it happens." MITRE: "Brute force becomes T1110, SQL injection T1190, a stolen key T1078." Honeytokens: "Fake keys planted to be stolen; using one sets off the alarm." | Press → twice |
| 16 | It watches, explains, and calls you | Decoy control, AI copilot, alerts | "Five decoys, nothing runs on the PC." "Ask the AI copilot 'who is 192.168.137.5?' — it works even offline." "One phone alert when an attack starts, no spam." | Press → twice |
| 17 | And everything around it | Six cards | Pick three: phishing analyzer, decoy documents, the internet tunnel. "It also packs into a single .exe." | — |
| 18 | One keystroke, end to end | A packet moves through Attacker → Paramiko → Virtual shell → MITRE mapper → SQLite → FastAPI | Read the line under each step. Key point: "The virtual shell answers 'root' from a fake file system; the command never touches Windows." | Press → five times |
| 19 | Five layers, one Python process | Stacked plates: Interface, Server, Brain, Traps, Memory | One sentence per layer: Vanilla JS + Chart.js + Leaflet; FastAPI + WebSockets; MITRE mapper + threat score + AI; Paramiko and raw sockets; SQLite + CSV audit. | Press → four times |

**Handover line:** "A honeypot invites attackers in, so the first question is: is KARMA itself safe?"

## Part 4 — Proof and future (slides 20–25, about 5 minutes)

Goal: answer the examiner's doubts before they ask, then close strongly.

| # | Slide | On screen | What to say | Do |
| --- | --- | --- | --- | --- |
| 20 | Built to be attacked | Four cards: Nothing runs, Console stays private, Floods are capped, Secrets stay hidden | "The shell is simulated — no programs, pipes or host files. The dashboard answers only the KARMA PC and needs a 43-character token. 10 logins and 600 requests a minute per IP. Passwords are redacted from logs." | — |
| 21 | Fourteen tests. All passed. | TC-01 to TC-14, each PASS | "These are the 14 system test cases from our report, run on the live platform." Explain two: TC-07 (auto-quarantine, block and unblock) and TC-13 (dashboard refused from outside). "Automated checks also run on Windows and Linux for every change." | Point at TC-07 and TC-13 |
| 22 | KARMA, counted | 5 decoys, 6 MITRE techniques, 14 test cases, 0 commands run on the host | Read each number with its line. Stress the 0. | Let the counters finish |
| 23 | Where it goes next | Today's limits vs future scope | "Honest limits: one laptop, rule-based detection, approximate geolocation." Then two future items: "firewall integration and distributed sensors." | — |
| 24 | They came for our data. We got theirs. | Conclusion | "KARMA shows one ordinary laptop can lure, profile and contain an attacker in real time. Every attacker who touches the trap leaves their IP, tools, commands and intent behind." | Pause after the headline |
| 25 | Thank you. Questions? | Team photos and roles | "Thank you. The honeypot is still running — ask us anything." | Leave this slide up during questions |

**During questions:** use [VIVA_QA.md](VIVA_QA.md). If asked to show something, switch to the dashboard: **▶ Replay** for an attacker's session, **📄 Report** for the incident report.
