const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let container = {innerHTML: ''};
const context = {window: {fetch: async () => {}, location: {href: 'http://localhost', origin: 'http://localhost'}},
    document: {addEventListener() {}, getElementById() { return container; }}, console, URL, Headers,
    setTimeout() {}, clearTimeout() {}, localStorage: {getItem() { return null; }}};
vm.createContext(context);
vm.runInContext(fs.readFileSync('frontend/js/app.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('frontend/js/ai_chat.js', 'utf8'), context);
context.renderHoneytokenList([{name: '<img src=x onerror=alert(1)>', type: '<script>x</script>', token_value: '<b>token</b>', hit_count: 0}]);
assert(!container.innerHTML.includes('<img'));
assert(container.innerHTML.includes('&lt;img'));
assert(!container.innerHTML.includes('<script>'));
const markdown = context.formatMarkdown('<img src=x onerror=alert(1)>\n```js\n<script>bad</script>\n```');
assert(!markdown.includes('<script>'));
assert(!markdown.includes('<img'));
assert(markdown.includes('&lt;script&gt;'));
console.log('Frontend escaping regression checks passed');
context.renderDocumentEvents([{timestamp:'2026-10-08',attack_type:'Document interaction confirmed',attacker_ip:'192.168.1.2',payload:JSON.stringify({file:'<img src=x onerror=alert(1)>',original_source_ip:'192.168.1.3'})}]);
assert(!container.innerHTML.includes('<img'));
assert(container.innerHTML.includes('&lt;img'));
const markers = [];
context.L = {circleMarker(location) {const marker = {location,bindPopup(html) {this.popup=html;},bindTooltip(text) {this.tooltip=text;}}; markers.push(marker); return marker;}};
vm.runInContext('leafMap = {}; mapMarkersLayer = {clearLayers(){},addLayer(){}};',context);
context.updateMapMarkers([
 {ip:'192.168.137.1',lat:12.9716,lng:77.5946,city:'Bengaluru',country:'India',geo_source:'configured_lab',geo_label:'Configured lab location',total_attempts:1,max_risk_score:25},
 {ip:'8.8.8.8',lat:null,lng:null},
 {ip:'invalid',lat:100,lng:0}
]);
assert.equal(markers.length,1);
assert(markers[0].popup.includes('Bengaluru'));
assert(markers[0].tooltip.includes('Configured lab location'));
assert(container.textContent.includes('1 of 3 loaded profiles mapped'));
console.log('Document alert and lab map regression checks passed');
