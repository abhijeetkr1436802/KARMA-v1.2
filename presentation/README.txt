KARMA — Exam Presentation
=========================

HOW TO RUN (no internet needed)
-------------------------------
1. Double-click index.html. It opens in Chrome or Edge.
2. Press F for full screen.
3. Navigate:
     Space / → / ↓ / PageDown ... next (some slides build step by step first)
     ← / ↑ / PageUp ............. back
     Home / End ................. first / last slide
   A presentation clicker works too (it sends PageUp/PageDown).

25 slides, about 18–22 minutes. It is designed at 1920×1080 and scales to any
screen or projector.

SLIDE ORDER
  1–2    Cold open, cover
  3–6    The problem: breaches worldwide and in India, 241 days, why firewalls fail
  7–9    The shift to honeypots, how a honeypot works, the KARMA name
  10     Objectives and scope
  11     Existing tools (firewall, Cowrie, T-Pot, Wazuh) vs KARMA
  12–13  Live attack map, "Type what an attacker types"
  14     The demo story: recon → web recon → break-in → loot → use the key → blocked
  15–17  Features, and everything around them (phishing analyzer, decoy documents,
         launcher and tester, .exe, HTTPS name, internet tunnel)
  18–19  Anatomy of an attack, anatomy of the stack
  20     Security of KARMA itself
  21–22  The 14 system test cases (TC-01 to TC-14, as in the project report), KARMA in numbers
  23     Limitations and future scope (same items as report section 6.4)
  24–25  Conclusion, thank you

SLIDES THAT BUILD (press → to advance inside the slide)
  3  Breaches worldwide: each press lights the next company and shows its real headline
  4  India: Star Health, Tata Technologies, CERT-In
  8  How a honeypot works: Lure → Trap → Profile → Contain (you can also drag the slider)
  9  KARMA: the letters open into the name
  14 The demo story: each press moves to the attacker's next stage
  15, 16  Features: each press shows the next real KARMA screen, large
  18 Anatomy of an attack: follow one keystroke through every library
  19 Anatomy of the stack: the five layers, one by one

LIVE SLIDE (13, "Type what an attacker types")
  Click the command line and type, or click an example. The verdict uses the same
  rules as KARMA's MITRE mapper and threat score. Press Esc before pressing
  Space again, so Space moves the slides instead of typing.

WHAT'S INSIDE
  index.html, styles.css, app.js   the presentation
  vendor/                          GSAP, three.js and fonts (offline copies)
  assets/news/                     real headline screenshots (sources on each slide)
  assets/shots/                    real screenshots of the KARMA dashboard
  assets/video/                    real recording of the live attack map
  assets/team/                     team photos

HEADLINE SOURCES
  Salesforce  TechCrunch, 3 Oct 2025      Coupang  TechCrunch, 1 Dec 2025
  Co-op       TechCrunch, 16 Jul 2025     JLR      City AM, 22 Oct 2025
  Canvas      KrebsOnSecurity, 7 May 2026 Star Health  TechCrunch, 9 Oct 2024
  Tata Tech.  BleepingComputer, 4 Mar 2025 CERT-In  Morung Express, 2026
  Stats: IBM Cost of a Data Breach 2025; Verizon DBIR 2025.
