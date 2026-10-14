'use strict';
/* KARMA presentation deck — navigation, three.js field, reveals, diagrams */

const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const deck = document.getElementById('deck');
const slides = [...document.querySelectorAll('.slide')];
const ACCENT = {amber:'#f7a53b', red:'#f4524b', green:'#2fd27a', blue:'#4ea2ff'};

/* ---------- build the two SVG diagrams ---------- */
function honeypotSVG() {
  return `<svg viewBox="0 0 1000 300" role="img" aria-label="An attacker aims at the production server; the attack curves into the KARMA honeypot instead.">
    <defs>
      <radialGradient id="hg" cx=".5" cy=".4" r=".7"><stop offset="0" stop-color="#fcd34d"/><stop offset="1" stop-color="#b45309"/></radialGradient>
      <marker id="arw" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0l10 5-10 5z" fill="#f4524b"/></marker>
    </defs>
    <!-- attacker -->
    <g transform="translate(70 150)">
      <circle r="46" fill="rgba(244,82,75,.14)" stroke="#f4524b" stroke-width="2.5"/>
      <path d="M-16 24V-2Q-16-30 0-34Q16-30 16-2V24Z" fill="none" stroke="#fca5a5" stroke-width="2.5"/>
      <path d="M-12-34Q-16-56 0-58Q16-56 12-34Q4-44 0-44Q-4-44-12-34Z" fill="none" stroke="#fca5a5" stroke-width="2.5"/>
      <text y="80" text-anchor="middle" fill="#aeb9d2" font-family="Sora,sans-serif" font-size="16" font-weight="600">Attacker</text>
    </g>
    <!-- production server (real, untouched) -->
    <g transform="translate(760 56)">
      <rect width="92" height="150" rx="12" fill="rgba(47,210,122,.1)" stroke="#2fd27a" stroke-width="2.5"/>
      <path d="M20 26h52M20 46h52M20 66h52" stroke="#2fd27a" stroke-width="4" stroke-linecap="round" opacity=".6"/>
      <circle cx="26" cy="104" r="5" fill="#2fd27a"/><circle cx="26" cy="124" r="4" fill="#2fd27a" opacity=".5"/>
      <text x="46" y="182" text-anchor="middle" fill="#2fd27a" font-family="Sora,sans-serif" font-size="14" font-weight="600">Production</text>
      <text x="46" y="200" text-anchor="middle" fill="#6b7794" font-family="Inter,sans-serif" font-size="12">untouched</text>
    </g>
    <!-- honeypot -->
    <g transform="translate(470 210)">
      <circle r="150" fill="none" stroke="#f7a53b" stroke-width="2" opacity="0" class="lure-r"/>
      <circle r="150" fill="none" stroke="#f7a53b" stroke-width="2" opacity="0" class="lure-r" style="animation-delay:1s"/>
      <circle r="150" fill="none" stroke="#f7a53b" stroke-width="2" opacity="0" class="lure-r" style="animation-delay:2s"/>
      <path d="M0-66l58 33v66L0 66l-58-33v-66z" fill="url(#hg)" stroke="#fde68a" stroke-width="3"/>
      <text y="-4" text-anchor="middle" fill="#fff7e6" font-family="Sora,sans-serif" font-size="20" font-weight="800" letter-spacing="2">KARMA</text>
      <text y="18" text-anchor="middle" fill="#fde68a" font-family="Inter,sans-serif" font-size="11" font-weight="600" letter-spacing="1">HONEYPOT</text>
    </g>
    <!-- intended path (faint, to production) -->
    <path d="M140 150 Q450 70 760 120" fill="none" stroke="#f4524b" stroke-width="2" stroke-dasharray="3 9" opacity=".35"/>
    <!-- actual path: curves into honeypot -->
    <path id="lurePath" d="M140 150 Q380 150 470 210" fill="none" stroke="#f4524b" stroke-width="3" marker-end="url(#arw)"/>
    <circle r="7" fill="#f4524b" class="attack-dot"><animateMotion dur="3s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;.7;1" calcMode="linear" path="M140 150 Q380 150 470 210"/><animate attributeName="opacity" dur="3s" repeatCount="indefinite" values="0;1;1;0;0" keyTimes="0;.05;.68;.72;1"/></circle>
  </svg>`;
}
function archSVG() {
  const box = (x,y,w,label,sub,col) => `<g transform="translate(${x} ${y})">
    <rect width="${w}" height="92" rx="14" fill="rgba(255,255,255,.03)" stroke="${col}" stroke-width="2"/>
    <text x="${w/2}" y="40" text-anchor="middle" fill="#f3f6fd" font-family="Sora,sans-serif" font-size="17" font-weight="700">${label}</text>
    <text x="${w/2}" y="64" text-anchor="middle" fill="#aeb9d2" font-family="Inter,sans-serif" font-size="12.5">${sub}</text></g>`;
  const flow = (x) => `<g transform="translate(${x} 46)"><line x1="0" y1="0" x2="46" y2="0" stroke="#6b7794" stroke-width="2"/><path d="M40-5l8 5-8 5z" fill="#6b7794"/><circle r="4" fill="#f7a53b"><animate attributeName="cx" values="0;46" dur="1.8s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;1;0" dur="1.8s" repeatCount="indefinite"/></circle></g>`;
  return `<svg viewBox="0 0 1000 150" role="img" aria-label="Attack flow: a probe hits a decoy sensor, is scored and classified, stored, streamed to the dashboard and pushed to your phone.">
    ${box(0,30,150,'Attack probe','SSH · Web · FTP','#f4524b')}
    ${flow(152)}
    ${box(206,30,168,'Decoy sensor','Paramiko · sockets','#f7a53b')}
    ${flow(376)}
    ${box(430,30,168,'Score &amp; classify','MITRE · threat engine','#4ea2ff')}
    ${flow(600)}
    ${box(654,30,150,'Store &amp; stream','SQLite · WebSocket','#2fd27a')}
    ${flow(806)}
    ${box(860,30,140,'You','Dashboard · phone','#f7a53b')}
  </svg>`;
}
document.getElementById('howStage').innerHTML = honeypotSVG();
document.getElementById('archStage').innerHTML = archSVG();
// lure ring keyframes injected once
const st = document.createElement('style');
st.textContent = '@keyframes lure{0%{r:150px;opacity:0}40%{opacity:.5}100%{r:70px;opacity:0}}.lure-r{animation:lure 3s linear infinite}@media(prefers-reduced-motion:reduce){.lure-r,.attack-dot{animation:none;opacity:.4}}';
document.head.appendChild(st);

/* ---------- dot nav ---------- */
const dotsWrap = document.getElementById('dots');
slides.forEach((s,i) => {
  const b = document.createElement('button');
  b.setAttribute('aria-label', 'Slide ' + (i+1));
  b.onclick = () => goto(i);
  dotsWrap.appendChild(b);
});
const dots = [...dotsWrap.children];
const counter = document.getElementById('counter');
const progress = document.getElementById('progress');
const total = slides.length;
counter.querySelector('b').nextSibling.textContent = ' / ' + String(total).padStart(2,'0');

/* ---------- active slide tracking ---------- */
let current = -1;
function setActive(i) {
  if (i === current) return;
  current = i;
  slides.forEach((s,n) => s.classList.toggle('active', n===i));
  dots.forEach((d,n) => d.classList.toggle('on', n===i));
  counter.querySelector('b').textContent = String(i+1).padStart(2,'0');
  progress.style.width = (i/(total-1)*100) + '%';
  const accent = ACCENT[slides[i].dataset.accent] || ACCENT.amber;
  if (field) field.setColor(accent);
  // stagger the reveals in this slide
  const items = slides[i].querySelectorAll('.r');
  items.forEach((el,n) => setTimeout(()=>el.classList.add('in'), reduced?0:n*85));
  // play / pause the attack-map video
  const v = slides[i].querySelector('video');
  document.querySelectorAll('video').forEach(x => { if (x!==v){x.pause();} });
  if (v) v.play().catch(()=>{});
}

const io = new IntersectionObserver(es => {
  es.forEach(e => { if (e.isIntersecting) setActive(slides.indexOf(e.target)); });
}, {root:deck, threshold:.55});
slides.forEach(s => io.observe(s));

/* ---------- navigation ---------- */
function goto(i) {
  i = Math.max(0, Math.min(total-1, i));
  slides[i].scrollIntoView({behavior: reduced?'auto':'smooth'});
}
function next(){ goto(current+1); }
function prev(){ goto(current-1); }

addEventListener('keydown', e => {
  if (['ArrowDown','ArrowRight','PageDown',' '].includes(e.key)) { e.preventDefault(); next(); }
  else if (['ArrowUp','ArrowLeft','PageUp'].includes(e.key)) { e.preventDefault(); prev(); }
  else if (e.key==='Home'){ e.preventDefault(); goto(0); }
  else if (e.key==='End'){ e.preventDefault(); goto(total-1); }
  else if (e.key==='f'||e.key==='F'){ document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen().catch(()=>{}); }
});

/* hide the hint after first interaction */
const hint = document.getElementById('hint');
let hidTimer = setTimeout(()=>hint.style.opacity='0', 6000);
addEventListener('keydown', ()=>{ clearTimeout(hidTimer); hint.style.opacity='0'; }, {once:true});

/* ---------- animated counters ---------- */
const counted = new WeakSet();
function runCount(el) {
  if (counted.has(el)) return; counted.add(el);
  const target = +el.dataset.count, suffix = el.dataset.suffix || '';
  if (reduced || target===0){ el.textContent = target + suffix; return; }
  const dur = 1100, t0 = performance.now();
  const step = t => {
    const k = Math.min(1,(t-t0)/dur), e = 1-Math.pow(1-k,3);
    el.textContent = Math.round(target*e) + suffix;
    if (k<1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
const countIO = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) runCount(e.target); }), {threshold:.6});
document.querySelectorAll('[data-count]').forEach(el => countIO.observe(el));

/* ---------- three.js drifting field ---------- */
let field = null;
(function three(){
  if (reduced || !window.THREE) return;
  const canvas = document.getElementById('bg');
  const renderer = new THREE.WebGLRenderer({canvas, alpha:true, antialias:true});
  renderer.setPixelRatio(Math.min(devicePixelRatio,1.5));
  const scene = new THREE.Scene();
  const cam = new THREE.PerspectiveCamera(60, innerWidth/innerHeight, .1, 100);
  cam.position.z = 26;

  const N = 1400;
  const pos = new Float32Array(N*3);
  for (let i=0;i<N;i++){
    pos[i*3]   = (Math.random()-.5)*90;
    pos[i*3+1] = (Math.random()-.5)*60;
    pos[i*3+2] = (Math.random()-.5)*50;
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(pos,3));
  const mat = new THREE.PointsMaterial({size:.13, color:new THREE.Color(ACCENT.amber), transparent:true, opacity:.55, depthWrite:false});
  const pts = new THREE.Points(geo, mat);
  scene.add(pts);

  const target = new THREE.Color(ACCENT.amber);
  field = { setColor(hex){ target.set(hex); } };

  let mx=0,my=0;
  addEventListener('pointermove', e => { mx=(e.clientX/innerWidth-.5); my=(e.clientY/innerHeight-.5); });

  function resize(){ cam.aspect=innerWidth/innerHeight; cam.updateProjectionMatrix(); renderer.setSize(innerWidth,innerHeight); }
  addEventListener('resize', resize); resize();

  function loop(t){
    pts.rotation.y = t*0.00003;
    pts.rotation.x = Math.sin(t*0.00002)*.1;
    cam.position.x += (mx*6 - cam.position.x)*.03;
    cam.position.y += (-my*4 - cam.position.y)*.03;
    cam.lookAt(0,0,0);
    mat.color.lerp(target, .04);
    renderer.render(scene,cam);
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
})();

/* kick off the first slide */
setActive(0);
