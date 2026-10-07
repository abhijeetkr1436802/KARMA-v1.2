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
