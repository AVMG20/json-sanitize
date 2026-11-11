import './style.css';
import {Sanitize, Status, Load, Unload} from '../wailsjs/go/main/App';
import {ClipboardSetText} from '../wailsjs/runtime/runtime';

const $ = (id) => document.getElementById(id);
const ta = $('ta'), hl = $('hl'), editor = $('editor');
const HL_LIMIT = 300 * 1024;
const TYPE_COLORS = {PERSON: 'var(--violet)', EMAIL: 'var(--accent)', PHONE: 'var(--green)', ADDRESS: 'var(--amber)'};

const state = {busy: false, original: null, changes: [], status: null, statusAt: 0, lastWarm: 0, tab: 'json'};

// ---------- highlighting ----------
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const PH = /\[[A-Z][A-Z_]*_\d+\]/g;
const TOKEN = /"(?:[^"\\\n]|\\.)*"?|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\btrue\b|\bfalse\b|\bnull\b|[{}\[\],:]/g;

function highlight(src) {
  let out = '', last = 0, m;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(src))) {
    const t = m[0];
    out += esc(src.slice(last, m.index));
    last = m.index + t.length;
    if (t[0] === '"') {
      const isKey = /^\s*:/.test(src.slice(last, last + 64));
      let html = esc(t);
      if (!isKey) html = html.replace(PH, (p) => `<span class="ph">${p}</span>`);
      out += `<span class="${isKey ? 't-key' : 't-str'}">${html}</span>`;
    } else if (/^[{}\[\],:]$/.test(t)) out += `<span class="t-p">${t}</span>`;
    else if (/^[tfn]/.test(t)) out += `<span class="t-lit">${t}</span>`;
    else out += `<span class="t-num">${t}</span>`;
  }
  return out + esc(src.slice(last));
}

function render() {
  const v = ta.value;
  const big = v.length > HL_LIMIT;
  ta.classList.toggle('plain', big);
  hl.classList.toggle('plain', big);
  if (!big) hl.innerHTML = highlight(v) + '\n';
  syncScroll();
}
function syncScroll() { hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; }
ta.addEventListener('scroll', syncScroll);

// ---------- footer hint ----------
let hintTimer;
function updateHint() {
  const h = $('hint'), v = ta.value;
  h.className = 'hint';
  if (!v.trim()) { h.textContent = 'Paste JSON to start'; return; }
  try {
    JSON.parse(v);
    const kb = new Blob([v]).size / 1024;
    h.classList.add('ok');
    h.textContent = `Valid JSON · ${kb >= 1000 ? (kb / 1024).toFixed(1) + ' MB' : kb.toFixed(1) + ' KB'} · ${v.split('\n').length} lines`;
  } catch (e) {
    h.classList.add('error');
    h.textContent = e.message;
  }
}
function showError(msg) {
  const h = $('hint'); h.className = 'hint error'; h.textContent = msg; h.title = msg;
}

ta.addEventListener('input', () => {
  render();
  clearTimeout(hintTimer);
  hintTimer = setTimeout(() => { $('hint').title = ''; updateHint(); }, 150);
});
ta.addEventListener('paste', () => { setTimeout(warmUp, 0); });

function warmUp() {
  const s = state.status;
  if (!s || s.state !== 'unloaded' || Date.now() - state.lastWarm < 30000) return;
  state.lastWarm = Date.now();
  Load().catch(() => {}).then(pollStatus);
}

// ---------- tabs ----------
function setTab(t) {
  state.tab = t;
  document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === t));
  $('panel-json').hidden = t !== 'json';
  $('panel-changes').hidden = t !== 'changes';
  if (t === 'json') ta.focus();
}
document.querySelectorAll('.tab').forEach((b) => b.addEventListener('click', () => setTab(b.dataset.tab)));

// ---------- sanitize ----------
const lit = (s) => {
  try { const v = JSON.parse(s); return typeof v === 'string' ? v : String(s); } catch { return String(s); }
};

function setBusy(b) {
  state.busy = b;
  ta.readOnly = b;
  editor.classList.toggle('busy', b);
  $('progress').classList.toggle('on', b);
  $('go').disabled = b;
  document.querySelector('#go .spin').hidden = !b;
  $('go-text').textContent = b ? 'Sanitizing…' : 'Sanitize';
}

async function sanitize() {
  if (state.busy) return;
  const input = ta.value;
  if (!input.trim()) { showError('Nothing to sanitize'); return; }
  try { JSON.parse(input); } catch (e) { showError(e.message); return; }
  $('hint').title = '';
  setBusy(true);
  try {
    const res = await Sanitize(input);
    if (!res.valid) {
      showError('Structure changed, input left untouched' + (res.diffs?.length ? `: ${res.diffs[0]}` : ''));
      $('hint').title = (res.diffs || []).join('\n');
      return;
    }
    state.original = input;
    state.changes = res.changes || [];
    ta.value = res.output;
    ta.scrollTop = 0; ta.scrollLeft = 0;
    render();
    updateHint();
    $('revert').hidden = false;
    const n = state.changes.length;
    const s = $('summary');
    s.hidden = false;
    s.classList.toggle('warn', !!res.unmatched?.length);
    s.textContent = `${n} value${n === 1 ? '' : 's'} redacted · structure identical · ${(res.ms / 1000).toFixed(1)} s`
      + (res.unmatched?.length ? ` · ${res.unmatched.length} unmatched` : '');
    renderChanges(res.counts || {});
  } catch (e) {
    showError(String(e?.message || e));
  } finally {
    setBusy(false);
    pollStatus();
  }
}

$('go').addEventListener('click', sanitize);
window.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); sanitize(); }
});

$('revert').addEventListener('click', () => {
  if (state.original == null) return;
  ta.value = state.original;
  state.original = null;
  $('revert').hidden = true;
  $('summary').hidden = true;
  render(); updateHint(); ta.focus();
});

let copyTimer;
$('copy').addEventListener('click', async () => {
  if (!ta.value) return;
  try {
    await ClipboardSetText(ta.value);
  } catch (e) {
    try { await navigator.clipboard.writeText(ta.value); } catch { showError('Copy failed'); return; }
  }
  const b = $('copy');
  b.classList.add('done');
  $('copy-ico').textContent = '✓';
  $('copy-text').textContent = 'Copied';
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => {
    b.classList.remove('done');
    $('copy-ico').textContent = '⧉';
    $('copy-text').textContent = 'Copy';
  }, 1500);
});

// ---------- changes tab ----------
function renderChanges(counts) {
  const chips = $('chips'), list = $('list'), badge = $('badge');
  chips.textContent = ''; list.textContent = '';
  const n = state.changes.length;
  badge.hidden = false; badge.textContent = n;
  if (!n) {
    list.innerHTML = '<div class="empty"><strong>No personal data found</strong><span>The JSON was left as it was.</span></div>';
    return;
  }
  Object.entries(counts).sort((a, b) => b[1] - a[1]).forEach(([k, v]) => {
    const c = document.createElement('span');
    c.className = 'chip';
    c.style.setProperty('--c', TYPE_COLORS[k] || 'var(--muted)');
    c.innerHTML = `<i></i>${esc(k)} <b>${v}</b>`;
    chips.appendChild(c);
  });
  const head = document.createElement('div');
  head.className = 'row head';
  head.innerHTML = '<span>Path</span><span>Change</span><span>Reason</span>';
  list.appendChild(head);
  const frag = document.createDocumentFragment();
  for (const ch of state.changes) {
    const r = document.createElement('div');
    r.className = 'row';
    r.innerHTML = `<span class="path">${esc(ch.path)}</span>`
      + `<span class="diff"><span class="before">${esc(lit(ch.before))}</span><span class="arrow">→</span>`
      + `<span class="ph">${esc(lit(ch.after))}</span></span>`
      + `<span class="reasons">${(ch.reasons || []).map((x) => `<span class="reason">${esc(x)}</span>`).join('')}</span>`;
    frag.appendChild(r);
  }
  list.appendChild(frag);
}
$('list').innerHTML = '<div class="empty"><strong>Nothing sanitized yet</strong><span>Run Sanitize on the JSON tab to review changes here.</span></div>';

// ---------- model status ----------
const fmtSize = (b) => b >= 1e9 ? (b / 1e9).toFixed(1) + ' GB' : Math.round(b / 1e6) + ' MB';
function paintStatus() {
  const s = state.status;
  const dot = $('model-dot'), txt = $('model-text'), btn = $('model-btn'), box = $('model');
  if (!s) return;
  box.classList.toggle('error', s.state === 'unavailable');
  box.title = s.state === 'unavailable' ? (s.error || 'Model unavailable') : '';
  dot.className = 'dot';
  btn.hidden = false; btn.disabled = false;
  switch (s.state) {
    case 'loaded': {
      dot.classList.add('loaded');
      let t = `${s.model} · in RAM`;
      if (s.sizeBytes) t += ` · ${fmtSize(s.sizeBytes)}`;
      const left = s.expiresAt ? Math.max(0, Math.round((Date.parse(s.expiresAt) - Date.now()) / 1000)) : null;
      if (left != null && !isNaN(left)) t += ` · unloads in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
      txt.textContent = t; btn.textContent = 'Unload'; break;
    }
    case 'unloaded':
      txt.textContent = `${s.model} · not loaded`; btn.textContent = 'Load'; break;
    case 'loading': case 'starting':
      dot.classList.add('loading');
      txt.textContent = s.state === 'starting' ? 'Starting Ollama…' : `Loading ${s.model}…`;
      btn.hidden = true; break;
    default:
      dot.classList.add('error');
      txt.textContent = s.error ? `${s.model || 'Model'} · unavailable` : 'Model unavailable';
      btn.textContent = 'Retry'; break;
  }
}
async function pollStatus() {
  try { state.status = await Status(); }
  catch (e) { state.status = {model: '', state: 'unavailable', error: String(e)}; }
  paintStatus();
}
$('model-btn').addEventListener('click', async () => {
  const s = state.status;
  if (!s) return;
  $('model-btn').disabled = true;
  if (s.state === 'loaded') { await Unload().catch(() => {}); }
  else {
    state.status = {...s, state: 'loading'}; paintStatus();
    Load().catch(() => {}).then(pollStatus);
    return;
  }
  pollStatus();
});
setInterval(() => { if (!document.hidden) pollStatus(); }, 2000);
setInterval(() => { if (!document.hidden && state.status?.state === 'loaded') paintStatus(); }, 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) pollStatus(); });

render(); updateHint(); pollStatus(); ta.focus();
