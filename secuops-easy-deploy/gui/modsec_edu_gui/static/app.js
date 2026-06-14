'use strict';
// modsec_edu_gui frontend — vanilla JS.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
async function getJSON(u) { return (await fetch(u)).json(); }
async function postJSON(u, b) { return (await fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) })).json(); }
function toast(m, ms = 2800) { const t = $('#toast'); t.textContent = m; t.classList.remove('hidden'); clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add('hidden'), ms); }

const TITLES = { dashboard: '대시보드', config: '구성 · CRS', analyzer: 'SecRule 분석기', rules: 'SecRule 관리', audit: 'audit 로그', siem: 'SIEM 연동', scenarios: '침해대응 훈련 (30)' };
function switchView(v) {
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  $$('.view').forEach(s => s.classList.toggle('hidden', s.id !== 'view-' + v));
  $('#view-title').textContent = TITLES[v] || v;
  ({ config: loadConfig, analyzer: loadCrsSample, rules: loadRules, audit: loadAudit, siem: loadSiem, scenarios: loadScenarios }[v] || (() => { }))();
}

async function loadStatus() {
  const s = await getJSON('/api/status');
  $('#st-apache').textContent = s.apache || 'Apache —';
  $('#st-engine').textContent = 'Engine ' + (s.engine || '—');
  $('#st-rules').textContent = 'GUI룰 ' + (s.edu_rule_count ?? '—');
  $('#st-audit').textContent = 'audit ' + (s.audit_mb ?? '—') + 'MB';
  const cards = [
    ['Apache', s.apache_running ? '가동중' : '중지', s.apache_running ? 'sm ok' : 'sm bad'],
    ['ModSecurity', s.modsec_version || '—', 'sm'],
    ['OWASP CRS', s.crs_version || '—', 'sm'],
    ['SecRuleEngine', s.engine || '—', (s.engine === 'On' ? 'sm ok' : 'sm')],
    ['GUI 룰 수', s.edu_rule_count ?? '—', ''],
    ['audit 로그', (s.audit_mb ?? '—') + ' MB', 'sm'],
  ];
  $('#dash-cards').innerHTML = cards.map(([k, v, c]) => `<div class="card"><div class="k">${esc(k)}</div><div class="v ${c || ''}">${esc(v)}</div></div>`).join('');
}

let FORM = null;
async function loadConfig() {
  const c = await getJSON('/api/config');
  FORM = c.form;
  $('#cfg-modsec').innerHTML = `<tr><th>지시어</th><th>값</th></tr>` + Object.entries(c.modsec).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');
  $('#cfg-paths').innerHTML = Object.entries(c.paths).map(([k, v]) => `<div>${esc(k)}: <b>${esc(v)}</b></div>`).join('');
  $('#cfg-crs').innerHTML = (c.crs_families || []).map(f => `<div class="crs-row"><span>${esc(f.file)}</span><b>${f.rules} rules</b></div>`).join('') || '<p class="note">CRS 파일을 찾지 못함</p>';
}

async function loadCrsSample() {
  const p = $('#crs-prefix').value;
  const d = await getJSON('/api/crs_sample?prefix=' + encodeURIComponent(p));
  $('#crs-sample').innerHTML = `<p class="note">${esc(d.file || '(파일 없음)')}</p>` + (d.rules || []).map(r => `<div class="codeln" style="margin-bottom:8px">${esc(r)}</div>`).join('');
}
$('#crs-prefix') && ($('#crs-prefix').onchange = loadCrsSample);

// analyzer
$('#an-sample').onclick = () => { $('#an-input').value = `SecRule ARGS "@rx (?i)union\\s+select" "id:942100,phase:2,t:none,t:lowercase,deny,status:403,msg:'SQL Injection',severity:'CRITICAL'"`; };
$('#an-btn').onclick = async () => {
  const r = await postJSON('/api/rule/analyze', { rule: $('#an-input').value });
  if (r.error) { $('#an-out').innerHTML = `<p class="result err">${esc(r.error)}</p>`; return; }
  const head = `<div class="an-head"><span class="an-chip">변수 <b>${esc(r.variables)}</b></span>
    <span class="an-chip">연산자 <b>${esc(r.operator)}</b></span>
    <span class="an-chip">패턴 <b>${esc(r.pattern)}</b></span></div>`;
  const desc = { id: '룰 고유 ID', phase: '검사 단계(1헤더/2본문)', deny: '차단', pass: '통과(로그만)', block: 'CRS 차단 정책 적용', drop: '연결 끊기', status: '응답 코드', log: '감사로그 기록', nolog: '로그 안 함', msg: '설명', severity: '심각도', 't': '입력 변환' };
  const opts = (r.actions || []).map(a => { const k = a.split(':')[0]; return `<div class="an-opt"><span class="k">${esc(a)}</span><span class="note" style="margin:0">${esc(desc[k] || '')}</span></div>`; }).join('');
  $('#an-out').innerHTML = head + `<div class="panel" style="margin-top:8px"><div class="panel-h">액션 ${r.actions.length}개</div><div class="panel-b" style="padding:0">${opts}</div></div>`;
};

// rule form
function fillForm() {
  if (!FORM) return;
  $('#f-var').innerHTML = FORM.variables.map(v => `<option>${esc(v)}</option>`).join('');
  $('#f-op').innerHTML = FORM.operators.map(v => `<option>${esc(v)}</option>`).join('');
  $('#f-action').innerHTML = FORM.actions.map(v => `<option>${esc(v)}</option>`).join('');
  $('#f-sev').innerHTML = FORM.severities.map(v => `<option>${esc(v)}</option>`).join('');
  $('#f-transforms').innerHTML = FORM.transforms.map(t => `<label><input type="checkbox" value="${esc(t)}" ${t === 'none' ? 'checked' : ''}> ${esc(t)}</label>`).join('');
}
let lastRule = '';
function bindRuleForm() {
  $('#btn-preview').onclick = async () => {
    const f = $('#rule-form'); const o = {};
    new FormData(f).forEach((v, k) => o[k] = v);
    o.transforms = $$('#f-transforms input:checked').map(c => c.value);
    if (!o.transforms.length) o.transforms = ['none'];
    const r = await postJSON('/api/rule/preview', o);
    if (r.rule) { lastRule = r.rule; $('#rule-cmd').textContent = r.rule; $('#btn-apply').disabled = false; }
    else { $('#rule-cmd').textContent = '오류: ' + (r.error || ''); $('#btn-apply').disabled = true; }
    $('#rule-result').innerHTML = '';
  };
  $('#btn-apply').onclick = async () => {
    const r = await postJSON('/api/rule/apply', { rule: lastRule });
    if (r.ok) { $('#rule-result').innerHTML = `<span class="ok">✔ ${esc(r.note || '적용됨')}</span>`; toast('SecRule 적용 + reload'); }
    else { $('#rule-result').innerHTML = `<span class="err">✘ ${esc(r.error || '')}\n${esc(r.detail || '')}</span>`; toast('문법오류 — 적용 안 됨(설정 보존)'); }
    $('#btn-apply').disabled = true; loadRules(); loadStatus();
  };
}
async function loadRules() {
  const d = await getJSON('/api/rules');
  $('#rules-next').textContent = '다음 id ' + d.next_id;
  $('#rules-list').innerHTML = (d.rules || []).map(r => `<div class="rrow">
    <span class="sid">${esc(r.id || '?')}</span><span class="msg">${esc(r.msg || '')}</span>
    <span class="badge">${esc((r.variables || '').slice(0, 18))}</span>
    <span class="del" data-id="${esc(r.id)}">삭제</span></div>`).join('') || '<p class="note">아직 GUI 룰이 없습니다.</p>';
  $$('.del', $('#rules-list')).forEach(b => b.onclick = async () => {
    if (!confirm('id ' + b.dataset.id + ' 룰 삭제?')) return;
    const r = await postJSON('/api/rule/delete', { id: b.dataset.id });
    toast(r.ok ? '삭제 + reload' : '삭제 실패: ' + (r.msg || '')); loadRules(); loadStatus();
  });
}

// audit
async function loadAudit() {
  const b = $('#audit-blocked').checked ? '&blocked=1' : '';
  const d = await getJSON('/api/audit?n=60' + b);
  $('#audit-list').innerHTML = (d.events || []).map(e => `<div class="aurow">
    <span class="st ${e.blocked ? 'block' : 'pass'}">${e.blocked ? '차단 ' + e.status : (e.status || '-')}</span>
    <span>${esc(e.method)}</span><span class="uri">${esc(e.uri)}</span>
    ${e.anomaly_score != null ? `<span class="sc">score ${e.anomaly_score}</span>` : ''}
    ${e.rules && e.rules.length ? `<span class="ids">[${e.rules.map(r => esc(r.id)).join(',')}]</span>` : ''}</div>`).join('') || '<p class="note">표시할 audit 이벤트가 없습니다.</p>';
}
$('#audit-blocked') && ($('#audit-blocked').onchange = loadAudit);

// siem
async function loadSiem() {
  const s = await getJSON('/api/siem');
  $('#siem-status').innerHTML = `<div><span class="dot ${s.integrated ? 'on' : 'off'}"></span> audit.log 연동: <b>${s.integrated ? '켜짐' : '꺼짐'}</b></div>
    <div><span class="dot ${s.agent_running ? 'on' : 'warn'}"></span> Wazuh 에이전트: <b>${s.agent_running ? '실행 중' : '확인 필요'}</b></div>
    <div><span class="dot on"></span> SIEM 매니저: <code>${esc(s.manager || '—')}</code></div>
    <div><span class="dot on"></span> audit 로그: <code>${esc(s.audit_log)}</code></div>`;
  $('#siem-detail').textContent = (s.status_raw || '').trim();
  $('#siem-enable').onclick = async () => { const r = await postJSON('/api/siem/enable', {}); toast(r.msg || ''); loadSiem(); };
}

// scenarios
async function loadScenarios() {
  const d = await getJSON('/api/scenarios');
  $('#scn-intro').textContent = d.intro || '';
  $('#scn-groups').innerHTML = (d.groups || []).map(g => `<span class="grp">${esc(g)}</span>`).join('');
  $('#scn-list').innerHTML = (d.scenarios || []).map(s => `
    <div class="scn"><div class="scn-h"><span class="lv">${esc(s.level || '')}</span><span class="id">${esc(s.id)}</span>
      <span class="ti">${esc(s.title)}</span><span class="stx">▾</span></div>
      <div class="scn-b">
        <h5>상황</h5><p>${esc(s.situation)}</p>
        <h5>공격 재현</h5><div class="codeln">${esc(s.attack)}</div>
        <h5>해야 할 일</h5><p>${esc(s.task)}</p>
        <h5>GUI 입력값</h5><p class="build">${esc(s.build)}</p>
        <h5>힌트</h5><p class="note">${esc(s.hint)}</p>
        <h5>배우는 개념</h5><p class="note">${esc(s.learn)}</p>
        <div class="scn-actions"><button class="btn btn-primary scn-check" data-id="${esc(s.id)}">검증</button>
          <span class="scn-verdict" id="v-${esc(s.id)}"></span></div>
        <div class="evid" id="e-${esc(s.id)}"></div></div></div>`).join('');
  $$('.scn-h').forEach(h => h.onclick = () => { const b = h.nextElementSibling; b.classList.toggle('open'); h.querySelector('.stx').textContent = b.classList.contains('open') ? '▴' : '▾'; });
  $$('.scn-check').forEach(btn => btn.onclick = async () => {
    const id = btn.dataset.id, v = $('#v-' + id), e = $('#e-' + id);
    v.textContent = '검증 중…'; v.className = 'scn-verdict';
    const r = await postJSON('/api/scenario/check', { id });
    v.textContent = r.ok ? '✔ 통과' : '✘ 미통과'; v.className = 'scn-verdict ' + (r.ok ? 'pass' : 'fail');
    e.textContent = (r.msg ? r.msg + '\n' : '') + (r.evidence ? JSON.stringify(r.evidence, null, 1) : '')
      + (r.configtest ? '\nconfigtest: ' + r.configtest : '') + (!r.ok && r.hint ? '\n💡 ' + r.hint : '');
  });
}

$$('.nav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
$('#btn-refresh').onclick = () => { loadStatus(); switchView($('.nav-item.active').dataset.view); toast('새로고침'); };
bindRuleForm();
// 폼 채우기용 config 선로딩
getJSON('/api/config').then(c => { FORM = c.form; fillForm(); });
loadStatus();
setInterval(() => { if ($('.nav-item.active').dataset.view === 'dashboard') loadStatus(); }, 10000);
