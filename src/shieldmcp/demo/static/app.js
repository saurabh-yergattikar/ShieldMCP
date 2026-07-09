// ShieldMCP live demo — drives the real pipeline via /api and animates stages.
'use strict';

const $ = (id) => document.getElementById(id);
const STAGES = ['stage1', 'stage2', 'stage3'];
const STAGE_INPUT = {
  stage1: (s) => s.tools,
  stage2: (s) => s.call,
  stage3: (s) => s.sample_response,
};
let SCENARIOS = [];
let activeId = null;
let running = false;

// ---------- theme ----------
const themeToggle = $('themeToggle');
themeToggle.addEventListener('click', () => {
  const root = document.documentElement;
  const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('shieldmcp-theme', next); } catch (e) {}
});
try {
  const saved = localStorage.getItem('shieldmcp-theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);
} catch (e) {}

// ---------- helpers ----------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

function stageCard(stage) { return $('card-' + stage); }
function setStageState(stage, state) {
  const card = stageCard(stage);
  card.classList.remove('scanning', 'pass', 'warn', 'block');
  if (state) card.classList.add(state);
  const st = $('status-' + stage);
  st.className = 'stage-status ' + (state || '');
  st.textContent = state === 'scanning' ? 'scanning' : (state || 'idle');
}

function resetStages() {
  STAGES.forEach((s) => {
    setStageState(s, null);
    $('status-' + s).textContent = 'idle';
    $('lat-' + s).textContent = '';
    $('body-' + s).innerHTML = '<p class="stage-hint">' + stageHint(s) + '</p>';
  });
  $('verdict').hidden = true;
}
function stageHint(stage) {
  return {
    stage1: 'Structural + semantic scan of every tool description.',
    stage2: 'Schema + payload scan of outbound call arguments.',
    stage3: 'Token-level instruction detection + context boundaries.',
  }[stage];
}

// Highlight suspicious spans in a text peek using alert snippets/messages.
function renderPeek(text, alerts) {
  let html = esc(text);
  const needles = new Set();
  alerts.forEach((a) => {
    if (a.details && a.details.snippet) needles.add(a.details.snippet);
    if (a.details && a.details.url) needles.add(a.details.url);
    if (a.details && a.details.matched) needles.add(a.details.matched);
  });
  // Generic injection keywords as a fallback highlight
  const kw = ['ignore all previous instructions', 'ignore previous instructions',
    'do not mention', 'do not inform the user', 'never mention this',
    'you must', 'IMPORTANT:', 'DROP TABLE', 'attacker', 'send_audit_log',
    'send_data', 'send_message', 'health_check'];
  needles.forEach((n) => {
    const e = esc(n);
    if (e.trim()) html = html.split(e).join('<span class="mark">' + e + '</span>');
  });
  kw.forEach((k) => {
    const e = esc(k);
    const re = new RegExp('(' + e.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
    html = html.replace(re, (m) => m.includes('class="mark"') ? m : '<span class="mark">' + m + '</span>');
  });
  return '<div class="code-peek">' + html + '</div>';
}

function renderStageBody(stage, result, scenario) {
  const body = $('body-' + stage);
  let html = '';
  const alerts = result.alerts || [];

  if (stage === 'stage3' && scenario) {
    html += renderPeek(scenario.sample_response, alerts);
  } else if (stage === 'stage2' && scenario) {
    const paramStr = JSON.stringify(scenario.call.params, null, 0);
    html += renderPeek(paramStr, alerts);
  } else if (stage === 'stage1' && scenario && alerts.length) {
    const desc = (scenario.tools[0] && scenario.tools[0].description) || '';
    if (desc) html += renderPeek(desc, alerts);
  }

  if (!alerts.length) {
    html += '<p class="stage-hint">No threats detected — passed clean.</p>';
  }
  alerts.forEach((a) => {
    html += '<div class="alert sev-' + a.severity + '">'
      + '<span class="alert-badge">' + esc(a.severity) + '</span>'
      + '<div class="alert-msg">' + esc(a.message)
      + '<span class="fam">' + esc(a.attack_family) + ' · action: ' + esc(a.action) + '</span>'
      + '</div></div>';
  });
  body.innerHTML = html;
}

function showVerdict(res) {
  const v = $('verdict');
  v.hidden = false;
  v.className = 'verdict ' + res.verdict;
  const map = {
    block: ['⛔', 'Attack blocked', 'ShieldMCP intercepted and blocked the attack before it reached the agent.'],
    warn: ['⚠️', 'Flagged for review', 'ShieldMCP raised warnings on suspicious activity.'],
    pass: ['✅', 'Clean — passed', 'All three stages passed. Legitimate traffic flows untouched.'],
  };
  const [icon, title, detail] = map[res.verdict];
  $('verdictIcon').textContent = icon;
  $('verdictTitle').textContent = title;
  $('verdictDetail').textContent = detail;
  $('verdictLatency').textContent = res.total_latency_ms.toFixed(1) + ' ms';
}

// ---------- run a scenario with staged animation ----------
async function runScenario(scenario) {
  if (running) return;
  running = true;
  $('runAll').disabled = true;
  resetStages();

  // header
  const tag = $('familyTag');
  tag.className = 'family-tag ' + scenario.family_role;
  tag.textContent = scenario.family_label;
  $('scenarioTitle').textContent = scenario.title;
  $('scenarioBlurb').textContent = scenario.blurb;

  // fetch live result up front, reveal per-stage with animation
  let res;
  try {
    const r = await fetch('/api/scenarios/' + scenario.id + '/run', { method: 'POST' });
    res = await r.json();
  } catch (e) {
    running = false; $('runAll').disabled = false;
    $('scenarioBlurb').textContent = 'Error contacting the ShieldMCP server.';
    return;
  }

  for (const stage of STAGES) {
    setStageState(stage, 'scanning');
    await sleep(620);
    const sr = res.stages[stage];
    setStageState(stage, sr.status);
    $('lat-' + stage).textContent = sr.latency_ms.toFixed(2) + ' ms  ·  ' + sr.alerts.length + ' alert' + (sr.alerts.length === 1 ? '' : 's');
    renderStageBody(stage, sr, scenario);
    await sleep(240);
    if (sr.status === 'block') break; // pipeline stops at first block
  }
  showVerdict(res);
  running = false;
  $('runAll').disabled = false;
}

// ---------- sidebar ----------
function renderSidebar() {
  const list = $('scenarioList');
  list.innerHTML = '';
  SCENARIOS.forEach((s) => {
    const li = document.createElement('li');
    li.className = 'scenario-item';
    li.dataset.id = s.id;
    li.innerHTML = '<div class="si-top"><span class="si-dot dot-' + s.family_role + '"></span>'
      + '<h4>' + esc(s.title) + '</h4></div>'
      + '<div class="si-fam">' + esc(s.family_label) + '</div>';
    li.addEventListener('click', () => selectScenario(s.id));
    list.appendChild(li);
  });
}
function selectScenario(id) {
  activeId = id;
  document.querySelectorAll('.scenario-item').forEach((el) =>
    el.classList.toggle('active', el.dataset.id === id));
  const s = SCENARIOS.find((x) => x.id === id);
  if (s) runScenario(s);
}

$('runAll').addEventListener('click', async () => {
  if (running) return;
  for (const s of SCENARIOS) {
    document.querySelectorAll('.scenario-item').forEach((el) =>
      el.classList.toggle('active', el.dataset.id === s.id));
    activeId = s.id;
    await runScenario(s);
    await sleep(500);
  }
});

// ---------- metrics ----------
const FAM_ORDER = ['tool_poisoning', 'indirect_prompt_injection', 'supply_chain', 'rug_pull', 'cross_tool_chain'];
const FAM_LABEL = {
  tool_poisoning: 'Tool poisoning',
  indirect_prompt_injection: 'Indirect prompt injection',
  supply_chain: 'Supply chain',
  rug_pull: 'Rug pull',
  cross_tool_chain: 'Cross-tool chain',
};

async function loadMetrics() {
  try {
    const r = await fetch('/api/eval');
    const d = await r.json();
    if (!d.available) return;
    const sum = d.summary;
    const overall = sum.overall || {};
    const asr = overall.asr != null ? overall.asr : (overall.attack_success_rate);
    if (asr != null) {
      $('statAsr').textContent = (asr <= 1 ? (asr * 100) : asr).toFixed(1) + '%';
      $('statAsrSub').textContent = (overall.detected || '') + '/' + (overall.total || '') + ' attacks blocked';
    }
    const benign = sum.benign || {};
    const pass = benign.pass_rate != null ? benign.pass_rate : benign.task_completion_rate;
    if (pass != null) $('statBenign').textContent = (pass <= 1 ? pass * 100 : pass).toFixed(1) + '%';

    // per-family chart
    const perFam = sum.by_family || sum.per_family || {};
    const chart = $('famChart');
    chart.innerHTML = '';
    const maxAsr = 25;
    FAM_ORDER.forEach((fam) => {
      const row = perFam[fam];
      if (!row) return;
      let famAsr = row.asr != null ? row.asr : row.attack_success_rate;
      if (famAsr != null && famAsr <= 1) famAsr = famAsr * 100;
      const div = document.createElement('div');
      div.className = 'fam-row';
      div.innerHTML = '<div class="fam-top"><span class="fam-name">' + FAM_LABEL[fam]
        + '</span><span class="fam-val">' + famAsr.toFixed(1) + '%</span></div>'
        + '<div class="fam-track"><div class="fam-fill" style="width:0%"></div></div>';
      chart.appendChild(div);
      requestAnimationFrame(() => {
        div.querySelector('.fam-fill').style.width = Math.min(100, (famAsr / maxAsr) * 100) + '%';
      });
    });
  } catch (e) { /* metrics optional */ }
}

async function loadConfig() {
  try {
    const r = await fetch('/api/config');
    const d = await r.json();
    const backends = [];
    if (d.stage1_backend) backends.push('S1:' + d.stage1_backend);
    if (d.stage3_backend) backends.push('S3:' + d.stage3_backend);
    $('backendText').textContent = backends.join('  ');
  } catch (e) {}
}

// ---------- playground ----------
$('openPlayground').addEventListener('click', () => { $('playgroundModal').hidden = false; });
$('closePlayground').addEventListener('click', () => { $('playgroundModal').hidden = true; });
$('playgroundModal').addEventListener('click', (e) => {
  if (e.target === $('playgroundModal')) $('playgroundModal').hidden = true;
});
$('pgRun').addEventListener('click', async () => {
  const body = {
    description: $('pgDescription').value,
    response: $('pgResponse').value,
    tool_name: 'user_tool',
  };
  try { body.params = JSON.parse($('pgParams').value || '{}'); }
  catch (e) { body.params = { value: $('pgParams').value }; }

  $('pgResult').innerHTML = '<p class="stage-hint">Analyzing…</p>';
  const r = await fetch('/api/analyze', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  const d = await r.json();
  const vmap = { block: ['⛔', 'Blocked', 'critical'], warn: ['⚠️', 'Flagged', 'warning'], pass: ['✅', 'Clean', 'good'] };
  const [icon, label] = vmap[d.verdict];
  let html = '<div class="verdict ' + d.verdict + '" style="margin-top:0"><div class="verdict-icon">' + icon
    + '</div><div class="verdict-text"><h3>' + label + '</h3><p>'
    + d.total_latency_ms.toFixed(1) + ' ms across all stages</p></div></div>';
  ['stage1', 'stage2', 'stage3'].forEach((st, i) => {
    const sr = d.stages[st];
    html += '<div style="margin-top:10px"><strong style="font-size:12px">Stage ' + (i + 1) + '</strong> — '
      + '<span class="stage-status ' + sr.status + '" style="display:inline-block">' + sr.status + '</span>';
    sr.alerts.forEach((a) => {
      html += '<div class="alert sev-' + a.severity + '"><span class="alert-badge">' + esc(a.severity)
        + '</span><div class="alert-msg">' + esc(a.message) + '</div></div>';
    });
    html += '</div>';
  });
  $('pgResult').innerHTML = html;
});

// ---------- boot ----------
async function boot() {
  const r = await fetch('/api/scenarios');
  SCENARIOS = await r.json();
  renderSidebar();
  loadMetrics();
  loadConfig();
  const params = new URLSearchParams(location.search);
  const want = params.get('scenario');
  const start = (want && SCENARIOS.find((s) => s.id === want)) ? want
    : (SCENARIOS.length ? SCENARIOS[0].id : null);
  if (start) selectScenario(start);
}
boot();
