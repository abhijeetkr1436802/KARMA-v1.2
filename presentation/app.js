/* KARMA deck: navigation, builds, motion. Works offline from file://. */
(() => {
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const stage = $('#stage'), chrome = $('#chrome'), chapter = $('#chapter');
const slides = $$('.slide');
slides.forEach(s => s.id = s.dataset.id);

/* ---------- fit the 1920×1080 stage to the window ---------- */
function fit() {
  const s = Math.min(innerWidth / 1920, innerHeight / 1080);
  stage.style.transform = `translate(${(innerWidth - 1920 * s) / 2}px, ${(innerHeight - 1080 * s) / 2}px) scale(${s})`;
  stage.style.left = stage.style.top = '0';
}
addEventListener('resize', fit); fit();

/* ---------- split headlines into masked words ---------- */
$$('.split').forEach(el => {
  el.innerHTML = el.textContent.trim().split(/\s+/).map(w => w === '|' ? '<br>' : `<span class="w"><span>${w}</span></span>`).join(' ');
});

/* ---------- slide-specific behaviour ---------- */
const NEWS = {
  world: [
    ['1 billion', "records claimed stolen from Salesforce customers' databases", 'TechCrunch · 3 October 2025'],
    ['34 million', 'customers of Korea’s biggest retailer exposed, unnoticed for months', 'TechCrunch · 1 December 2025'],
    ['6.5 million', 'Co-op member records stolen: every single one', 'TechCrunch · 16 July 2025'],
    ['£1.9 billion', 'cost to the UK economy: the most expensive cyber attack in British history', 'City AM · 22 October 2025'],
    ['275 million', 'students and staff threatened with a leak across ~9,000 schools and colleges', 'KrebsOnSecurity · 7 May 2026'],
  ],
  india: [
    ['31 million', "policyholders' names, addresses and medical reports posted online", 'TechCrunch · 9 October 2024'],
    ['1.4 TB', 'of files claimed stolen by the Hunters International ransomware gang', 'BleepingComputer · 4 March 2025'],
    ['29.44 lakh', 'cyber incidents handled by CERT-In across India in 2025 alone', 'Morung Express · CERT-In, 2025'],
  ],
};

function showNews(slide, i, animate = true) {
  const id = slide.dataset.id, d = NEWS[id][i];
  $$('.nm', slide).forEach(n => n.classList.toggle('on', +n.dataset.i === i));
  const clips = $$('.clip', slide);
  clips.forEach((c, k) => {
    if (k === i) {
      gsap.killTweensOf(c);
      gsap.set(c, { zIndex: 10 });
      animate && !RM
        ? gsap.fromTo(c, { opacity: 0, scale: 1.12, rotate: k % 2 ? 2.5 : -2.5, y: 30 }, { opacity: 1, scale: 1, rotate: 0, y: 0, duration: .7, ease: 'expo.out' })
        : gsap.set(c, { opacity: 1, scale: 1, rotate: 0, y: 0 });
    } else if (k < i) {
      gsap.to(c, { opacity: .5, scale: .9 - (i - k) * .03, rotate: (k % 2 ? 1 : -1) * (2 + i - k), x: -(i - k) * 26, y: -(i - k) * 22, zIndex: k, duration: .6, ease: 'expo.out' });
    } else {
      gsap.to(c, { opacity: 0, duration: .2, zIndex: 0 });
    }
  });
  const num = $(`#${id}Num`), cap = $(`#${id}Cap`), src = $(`#${id}Src`);
  num.textContent = d[0]; cap.textContent = d[1]; src.textContent = d[2];
  if (animate && !RM) {
    gsap.fromTo(num, { yPercent: 40, opacity: 0 }, { yPercent: 0, opacity: 1, duration: .6, ease: 'expo.out', delay: .12 });
    gsap.fromTo([cap, src], { opacity: 0, y: 14 }, { opacity: 1, y: 0, duration: .5, stagger: .06, delay: .22 });
  }
}

/* cold open terminal */
const TERM = [
  ['$ ', 'ssh root@aegis-gateway -p 2222'],
  ['', 'Welcome to Ubuntu 22.04.3 LTS', 'out'],
  ['root@aegis-gateway:~# ', 'whoami'],
  ['', 'root', 'out'],
  ['root@aegis-gateway:~# ', 'cat /etc/passwd'],
  ['', 'root:x:0:0:root:/root:/bin/bash', 'out'],
];
let termTimer;
function runTerm(done) {
  const el = $('#term'); clearTimeout(termTimer);
  if (RM) { el.innerHTML = TERM.map(l => l[0] + `<span class="u">${l[1]}</span>`).join('\n'); return done(); }
  let line = 0, ch = 0, html = '';
  const tick = () => {
    if (line >= TERM.length) { el.innerHTML = html + '<span class="cur"></span>'; return done(); }
    const [p, t, kind] = TERM[line];
    if (kind === 'out') { html += `<span class="ok">${t}</span>\n`; line++; el.innerHTML = html; termTimer = setTimeout(tick, 260); return; }
    ch++;
    el.innerHTML = html + p + `<span class="u">${t.slice(0, ch)}</span><span class="cur"></span>`;
    if (ch >= t.length) { html += p + `<span class="u">${t}</span>\n`; line++; ch = 0; termTimer = setTimeout(tick, 420); }
    else termTimer = setTimeout(tick, 38 + Math.random() * 50);
  };
  el.innerHTML = '<span class="cur"></span>'; termTimer = setTimeout(tick, 500);
}

/* 241-day grid */
const grid = $('#daysGrid');
grid.innerHTML = '<i></i>'.repeat(241);
function runDays() {
  const cells = $$('i', grid), num = $('#daysNum');
  cells.forEach(c => c.classList.remove('on'));
  const o = { v: 0 };
  gsap.killTweensOf(o);
  gsap.to(o, { v: 241, duration: RM ? 0 : 3.2, ease: 'power2.inOut', delay: .5, onUpdate() {
    const v = Math.round(o.v); num.textContent = v;
    for (let k = 0; k < v; k++) cells[k].classList.add('on');
  } });
}

/* how it works: four stages driven by the range and by → */
const howRange = $('#howRange');
function setHow(i, animate = true) {
  const s = $('#how');
  howRange.value = i;
  $$('.clause', s).forEach(c => c.classList.toggle('on', +c.dataset.i === i));
  $$('.explain', s).forEach(c => c.classList.toggle('on', +c.dataset.i === i));
  $$('.stop-names span', s).forEach((c, k) => c.classList.toggle('on', k <= i));
  howRange.style.background = `linear-gradient(90deg, #121110 ${i / 3 * 100}%, #cfc8bb ${i / 3 * 100}%)`;
  const bend = $('#pBend'), len = bend.getTotalLength(), pkt = $('.pkt', s);
  gsap.killTweensOf([bend, pkt, '#howTag', '#howLock']);
  gsap.set(bend, { strokeDasharray: len, strokeDashoffset: i >= 1 ? 0 : len });
  if (i >= 1 && animate && !RM) gsap.fromTo(bend, { strokeDashoffset: len }, { strokeDashoffset: 0, duration: .9, ease: 'power2.inOut' });
  // packet loops along the bent path while trapped
  if (i >= 1 && i < 3 && !RM) {
    const o = { t: 0 };
    gsap.to(o, { t: 1, duration: 1.6, repeat: -1, ease: 'none', onUpdate() { const p = bend.getPointAtLength(o.t * len); pkt.setAttribute('cx', p.x); pkt.setAttribute('cy', p.y); } });
    gsap.set(pkt, { opacity: 1 });
  } else gsap.set(pkt, { opacity: i === 0 ? 1 : 0, attr: { cx: 290, cy: 390 } });
  gsap.to('#howTag', { opacity: i >= 2 ? 1 : 0, y: i >= 2 ? 0 : 20, duration: .4 });
  gsap.to('#howLock', { opacity: i >= 3 ? 1 : 0, scale: i >= 3 ? 1 : .6, transformOrigin: '50% 50%', duration: .45, ease: 'back.out(2)' });
  $('#atkState').textContent = ['scanning…', 'inside the decoy', 'profiled · Linux', 'quarantined'][i];
  $('.p-bend').style.stroke = i >= 3 ? 'var(--red)' : '';
}
howRange.addEventListener('input', () => { setHow(+howRange.value); if (slides[cur].dataset.id === 'how') step = +howRange.value; });

/* KARMA reveal */
function setReveal(open) {
  const d = RM ? 0 : 1;
  $('#reveal').classList.toggle('open', open);
  gsap.to('#reveal .karma', { opacity: open ? 0 : 1, scale: open ? .8 : 1, duration: .6 * d, ease: 'expo.inOut' });
  gsap.to($$('#reveal .ac'), { opacity: open ? 1 : 0, x: open ? 0 : -40, duration: .7 * d, ease: 'expo.out', stagger: .08 * d, delay: open ? .25 * d : 0 });
}

/* features: one row lit, its real screen shown large */
function setFeat(s, i) {
  $$('.fr', s).forEach(r => r.classList.toggle('on', +r.dataset.i === i));
  $$('.fp', s).forEach(r => r.classList.toggle('on', +r.dataset.i === i));
  const pic = $(`.fp[data-i="${i}"]`, s);
  if (!RM) gsap.fromTo(pic, { scale: 1.06 }, { scale: 1, duration: 1.2, ease: 'expo.out' });
}

/* type an attack: the same rules as backend/engine/mitre_mapper.py + threat_score.py */
const RULES = [
  ['T1078', 'Valid Accounts (Honeytoken)', 'Initial Access', ['honeytoken', 'token_hit', 'AKIAIOSFODNN7EXAMPLE', 'secret-vault-admin'], ['HONEYTOKEN'], 95],
  ['T1190', 'Exploit Public-Facing Application', 'Initial Access', ['select', 'union', 'drop table', 'OR 1=1', 'exec', 'system(', '<script>', '../../', '/etc/passwd'], ['WEB_HONEYPOT'], 85],
  ['T1110', 'Brute Force', 'Credential Access', ['ssh_login_failed', 'brute_force', 'admin/password', 'root/root'], ['SSH_HONEYPOT', 'WEB_HONEYPOT'], 70],
  ['T1059', 'Command and Scripting Interpreter', 'Execution', ['whoami', 'id', 'uname', 'wget', 'curl', 'chmod', 'cat /etc', 'nc -e', 'bash -i', 'command_execution'], ['SSH_HONEYPOT', 'RAW_DECOY'], 90],
  ['T1046', 'Network Service Discovery', 'Discovery', ['port_scan', 'connect_probe', 'syn_scan'], ['RAW_DECOY', 'PORT_SCANNER', 'SSH_HONEYPOT'], 45],
  ['T1595', 'Active Scanning', 'Reconnaissance', ['directory_traversal', 'fuzzing', '/.env', '/wp-login.php', '/phpmyadmin'], ['WEB_HONEYPOT'], 55],
];
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function classify(input) {
  const text = input.trim();
  const web = /^\/|['"<]|\b(select|union)\b|\.\.\//i.test(text) && !/^(cat|ls|cd)\b/.test(text);
  const svc = web ? 'WEB_HONEYPOT' : 'SSH_HONEYPOT';
  const combined = (web ? 'web request ' : `ssh_command_execution ssh executed command: '${text}'`).toLowerCase() + ' ' + text.toLowerCase();
  for (const [id, name, tactic, kws, svcs, risk] of RULES) {
    if (!svcs.includes(svc)) continue;
    if (kws.some(k => new RegExp(`(?<!\\w)${esc(k.toLowerCase())}(?!\\w)`).test(combined))) return { svc, id, name, tactic, risk };
  }
  if (!web) return { svc, id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', risk: 60 };
  return { svc, id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance', risk: 50 };
}
// What the decoy answers (backend/sensors/virtual_shell.py and the web decoy)
function seen(cmd, svc) {
  if (svc === 'WEB_HONEYPOT') return 'A convincing corporate portal page.\nNothing looks wrong, but every byte\nyou sent has already been logged.';
  const c = cmd.split(/\s+/)[0];
  const out = {
    whoami: 'root', id: 'uid=0(root) gid=0(root) groups=0(root)', hostname: 'aegis-gateway',
    pwd: '/root', uname: 'Linux', ls: 'company  deploy.env  notes.txt',
    cat: cmd.includes('/etc/passwd') ? 'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Operations:/home/admin:/bin/bash' : 'cat: ' + (cmd.split(/\s+/)[1] || '') + ': No such file or directory',
  }[c];
  return out ?? `bash: ${c}: command not found`;
}
const atkInput = $('#atkInput');
function verdict() {
  const v = classify(atkInput.value || ' ');
  const score = v.risk < 75 ? Math.min(v.risk, 74) : v.risk;   // calculate_event_risk, first attempt
  $('#vSvc').textContent = v.svc === 'WEB_HONEYPOT' ? 'Web decoy · port 8080' : 'SSH decoy · port 2222';
  $('#vMitre').textContent = `${v.id} · ${v.name}`;
  $('#vTactic').textContent = v.tactic;
  $('#vScore').textContent = score;
  $('#vBar').style.width = score + '%';
  const q = score >= 75;
  $('#vAct').textContent = q ? 'Quarantines the attacker' : 'Logs it and keeps watching';
  $('#seenOut').textContent = seen(atkInput.value.trim(), v.svc);
  $('.v-act').classList.toggle('calm', !q);
}
atkInput.addEventListener('input', verdict);
$$('.examples button').forEach(b => b.addEventListener('click', () => { atkInput.value = b.dataset.ex; verdict(); atkInput.focus(); }));
verdict();

/* flow anatomy */
const SAY = [
  'The attacker thinks they reached a company server. They type a command to see who they are.',
  'Paramiko is a Python library that speaks real SSH, so the attacker’s own ssh client is completely fooled.',
  'Our virtual shell replies “root” from a fake filesystem. The command never touches Windows or the real disk.',
  'The MITRE mapper names the technique, T1059 Execution, and the threat score rates it 90 out of 100.',
  'SQLite stores the event with the IP, time and payload; a timestamped CSV copy keeps a separate audit trail.',
  'FastAPI pushes it over a WebSocket: the dashboard updates instantly and ntfy buzzes your phone.',
];
function setFlow(i) {
  const nodes = $$('#flow .node');
  nodes.forEach((n, k) => { n.classList.toggle('on', k === i); n.classList.toggle('done', k < i); });
  const n = nodes[i], p = $('#packet');
  const x = n.offsetLeft + n.offsetWidth / 2 - p.offsetWidth / 2;
  gsap.to(p, { x, duration: RM ? 0 : .7, ease: 'expo.inOut' });
  $('#packet code').textContent = ['whoami', 'whoami', 'root', 'T1059 · 90', 'saved', 'live → phone'][i];
  const say = $('#say');
  say.textContent = SAY[i];
  if (!RM) gsap.fromTo(say, { opacity: 0, y: 16 }, { opacity: 1, y: 0, duration: .5, ease: 'expo.out' });
}

/* stack anatomy */
function setStack(i) {
  $$('#plates .plate').forEach((p, k) => {
    p.classList.toggle('on', k === i);
    const z = (4 - k) * 80 + (k < i ? 110 : 0) + (k === i ? 45 : 0);
    gsap.to(p, { '--z': z, duration: RM ? 0 : .7, ease: 'expo.out' });
  });
  $$('#stack .ln').forEach((l, k) => l.classList.toggle('on', k === i));
}

function countUp(slide) {
  $$('[data-count]', slide).forEach(el => {
    const o = { v: 0 }, to = +el.dataset.count;
    gsap.to(o, { v: to, duration: RM ? 0 : 1.6, ease: 'power3.out', delay: .4, onUpdate() { el.textContent = Math.round(o.v); } });
  });
}

const HOOKS = {
  cold: { enter: s => { gsap.set($$('.cold-copy .w>span, .cold-copy .in', s), { opacity: 0 }); runTerm(() => entrance($('.cold-copy', s), 0)); }, noEntrance: true },
  cover: { enter: s => { $('video', s).play().catch(() => {}); if (!RM) gsap.fromTo($$('.ch', s), { yPercent: 18, opacity: 0 }, { yPercent: 0, opacity: 1, duration: 1.1, ease: 'expo.out', delay: .2 }); } },
  world: { enter: s => showNews(s, 0, true), step: (s, k) => showNews(s, k) },
  india: { enter: s => showNews(s, 0, true), step: (s, k) => showNews(s, k) },
  days: { enter: runDays },
  how: { enter: () => setHow(0, false), step: (s, k) => setHow(k) },
  reveal: { enter: () => setReveal(false), step: (s, k) => setReveal(k >= 1) },
  featA: { enter: s => setFeat(s, 0), step: setFeat },
  featB: { enter: s => setFeat(s, 0), step: setFeat },
  map: { enter: s => $('#mapVid').play().catch(() => {}) },
  type: { enter: () => { verdict(); } },
  anatomy: { enter: () => setFlow(0), step: (s, k) => setFlow(k) },
  stack: { enter: () => setStack(0), step: (s, k) => setStack(k) },
  nums: { enter: countUp },
};

/* ---------- entrances ---------- */
function entrance(root, delay = .25) {
  const words = $$('.split .w>span', root), ins = $$('.in', root);
  if (RM) { gsap.set([...words, ...ins], { opacity: 1, y: 0, yPercent: 0 }); return; }
  gsap.fromTo(words, { yPercent: 110, opacity: 1 }, { yPercent: 0, duration: 1, ease: 'expo.out', stagger: .055, delay });
  gsap.fromTo(ins, { y: 28, opacity: 0 }, { y: 0, opacity: 1, duration: .8, ease: 'expo.out', stagger: .08, delay: delay + .25 });
}

/* ---------- navigation ---------- */
let cur = -1, step = 0, busy = false;
const steps = s => +(s.dataset.steps || 0);
const INK = { 'f-paper': 'dark', 'f-amber': 'dark' };
function setChrome(s) {
  const dark = [...s.classList].some(c => INK[c]);
  chrome.classList.toggle('dark', dark);
  chapter.style.color = s.dataset.id === 'how' ? 'var(--paper-ink)' : '';
  chapter.textContent = s.dataset.chapter || '';
  $('#progress').style.width = ((slides.indexOf(s) + 1) / slides.length * 100) + '%';
}

function show(n, dir = 1) {
  n = Math.max(0, Math.min(slides.length - 1, n));
  if (n === cur || busy) return;
  const prev = slides[cur], next = slides[n];
  busy = true; cur = n; step = 0;
  next.classList.add('active');
  setChrome(next);
  if (prev) $$('video', prev).forEach(v => v.pause());
  const h = HOOKS[next.dataset.id] || {};
  if (!h.noEntrance) entrance(next);
  h.enter && h.enter(next);
  if (dir < 0 && steps(next) && h.step) { step = steps(next); h.step(next, step); }
  const done = () => { busy = false; if (prev) { prev.classList.remove('active'); gsap.set(prev, { clearProps: 'opacity,clipPath,y' }); } };
  if (!prev || RM) { gsap.set(next, { clipPath: 'none' }); done(); return; }
  gsap.to(prev, { opacity: 0, y: dir * -40, duration: .45, ease: 'power2.in' });
  gsap.fromTo(next, { clipPath: dir > 0 ? 'inset(100% 0% 0% 0%)' : 'inset(0% 0% 100% 0%)' },
    { clipPath: 'inset(0% 0% 0% 0%)', duration: .9, ease: 'expo.inOut', onComplete: () => { gsap.set(next, { clipPath: 'none' }); done(); } });
  location.hash = n + 1;
}
function nextStep() {
  const s = slides[cur], h = HOOKS[s.dataset.id] || {};
  if (step < steps(s) && h.step) { step++; h.step(s, step); return; }
  show(cur + 1, 1);
}
function prevStep() {
  const s = slides[cur], h = HOOKS[s.dataset.id] || {};
  if (step > 0 && h.step) { step--; h.step(s, step); return; }
  show(cur - 1, -1);
}

addEventListener('keydown', e => {
  const typing = document.activeElement === atkInput;
  if (typing && !['PageDown', 'PageUp', 'Escape'].includes(e.key)) return;
  if (document.activeElement === howRange && ['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
  if (['ArrowRight', 'ArrowDown', 'PageDown', ' ', 'Enter'].includes(e.key)) { e.preventDefault(); nextStep(); }
  else if (['ArrowLeft', 'ArrowUp', 'PageUp', 'Backspace'].includes(e.key)) { e.preventDefault(); prevStep(); }
  else if (e.key === 'Home') show(0, -1);
  else if (e.key === 'End') show(slides.length - 1, 1);
  else if (e.key === 'Escape') document.activeElement.blur();
  else if (e.key.toLowerCase() === 'f') { document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen().catch(() => {}); }
});
let wheelLock = 0;
addEventListener('wheel', e => {
  if (Math.abs(e.deltaY) < 25 || Date.now() < wheelLock) return;
  wheelLock = Date.now() + 900; e.deltaY > 0 ? nextStep() : prevStep();
}, { passive: true });
let tx = null;
addEventListener('touchstart', e => tx = e.touches[0].clientX, { passive: true });
addEventListener('touchend', e => { if (tx == null) return; const d = e.changedTouches[0].clientX - tx; if (Math.abs(d) > 60) d < 0 ? nextStep() : prevStep(); tx = null; });

/* ---------- background network (three.js) ---------- */
(function net() {
  if (!window.THREE) return;
  const canvas = $('#net');
  const r = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  r.setPixelRatio(Math.min(devicePixelRatio, 2)); r.setSize(1920, 1080, false);
  const scene = new THREE.Scene(), cam = new THREE.PerspectiveCamera(55, 1920 / 1080, 1, 2000);
  cam.position.z = 620;
  const N = 140, pos = [], vel = [];
  for (let i = 0; i < N; i++) { pos.push(new THREE.Vector3((Math.random() - .5) * 1500, (Math.random() - .5) * 860, (Math.random() - .5) * 500)); vel.push(new THREE.Vector3((Math.random() - .5) * .35, (Math.random() - .5) * .35, 0)); }
  const pg = new THREE.BufferGeometry(), parr = new Float32Array(N * 3);
  pg.setAttribute('position', new THREE.BufferAttribute(parr, 3));
  const pts = new THREE.Points(pg, new THREE.PointsMaterial({ color: 0xf7a53b, size: 4, transparent: true, opacity: .55 }));
  const MAXL = 900, lg = new THREE.BufferGeometry(), larr = new Float32Array(MAXL * 6);
  lg.setAttribute('position', new THREE.BufferAttribute(larr, 3));
  const lines = new THREE.LineSegments(lg, new THREE.LineBasicMaterial({ color: 0xf7a53b, transparent: true, opacity: .1 }));
  scene.add(pts, lines);
  let t = 0;
  (function loop() {
    t += .0015;
    for (let i = 0; i < N; i++) {
      if (!RM) pos[i].add(vel[i]);
      if (Math.abs(pos[i].x) > 760) vel[i].x *= -1;
      if (Math.abs(pos[i].y) > 440) vel[i].y *= -1;
      parr.set([pos[i].x, pos[i].y, pos[i].z], i * 3);
    }
    let c = 0;
    for (let i = 0; i < N && c < MAXL; i++) for (let j = i + 1; j < N && c < MAXL; j++) {
      if (pos[i].distanceToSquared(pos[j]) < 150 * 150) { larr.set([pos[i].x, pos[i].y, pos[i].z, pos[j].x, pos[j].y, pos[j].z], c * 6); c++; }
    }
    lg.setDrawRange(0, c * 2);
    pg.attributes.position.needsUpdate = lg.attributes.position.needsUpdate = true;
    scene.rotation.y = Math.sin(t) * .25; scene.rotation.x = Math.cos(t * .7) * .08;
    r.render(scene, cam);
    requestAnimationFrame(loop);
  })();
})();

/* ---------- start ---------- */
const start = Math.max(0, Math.min(slides.length - 1, (parseInt(location.hash.slice(1)) || 1) - 1));
document.fonts.ready.then(() => show(start));
window.__deck = { show, nextStep, prevStep, get cur() { return cur; }, get step() { return step; } };
})();
