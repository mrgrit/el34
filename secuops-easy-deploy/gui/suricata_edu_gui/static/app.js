'use strict';
// suricata_edu_gui frontend — vanilla JS.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
async function getJSON(u) { return (await fetch(u)).json(); }
async function postJSON(u, b) { return (await fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) })).json(); }
function toast(m, ms = 2800) { const t = $('#toast'); t.textContent = m; t.classList.remove('hidden'); clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add('hidden'), ms); }
function formData(f) { const o = {}; new FormData(f).forEach((v, k) => o[k] = v); $$('input[type=checkbox]', f).forEach(c => o[c.name] = c.checked); return o; }

const TITLES = { dashboard: '대시보드', config: '구성 · 디렉토리', analyzer: '룰 구조 분석기', rules: '탐지룰 관리', eve: '이벤트(eve.json)', siem: 'SIEM 연동', scenarios: '침해대응 훈련 (30)' };
function switchView(v) {
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  $$('.view').forEach(s => s.classList.toggle('hidden', s.id !== 'view-' + v));
  $('#view-title').textContent = TITLES[v] || v;
  ({ config: loadConfig, analyzer: () => { }, rules: loadRules, eve: loadEve, siem: loadSiem, scenarios: loadScenarios }[v] || (() => { }))();
}

async function loadStatus() {
  const s = await getJSON('/api/status');
  $('#st-ver').textContent = (s.version || '').replace('This is ', '').split(' RELEASE')[0] || 'Suricata —';
  $('#st-run').textContent = s.running ? '● 가동중' : '○ 중지';
  $('#st-rules').textContent = `룰 ${s.rules_loaded ?? '—'} (실패 ${s.rules_failed ?? '—'})`;
  $('#st-eve').textContent = `eve ${s.eve_mb ?? '—'}MB`;
  const cards = [
    ['Suricata', s.running ? '가동중' : '중지', s.running ? 'sm ok' : 'sm bad'],
    ['로딩된 룰', s.rules_loaded ?? '—', (s.rules_loaded > 0 ? '' : 'bad')],
    ['로딩 실패', s.rules_failed ?? '—', (s.rules_failed > 0 ? 'bad' : 'ok')],
    ['GUI 룰(local)', s.local_rule_count ?? '—', ''],
    ['eve.json', (s.eve_mb ?? '—') + ' MB', 'sm'],
    ['감시 IF', (s.interfaces || []).filter(i => i.name !== 'lo').map(i => i.name).join('+') || '—', 'sm'],
  ];
  $('#dash-cards').innerHTML = cards.map(([k, v, c]) => `<div class="card"><div class="k">${esc(k)}</div><div class="v ${c || ''}">${esc(v)}</div></div>`).join('');
}

async function loadConfig() {
  const c = await getJSON('/api/config');
  $('#cfg-net').innerHTML = `<tr><th>항목</th><th>값</th></tr>
    <tr><td>HOME_NET</td><td>${esc(c.yaml.HOME_NET)}</td></tr>
    <tr><td>EXTERNAL_NET</td><td>${esc(c.yaml.EXTERNAL_NET || '!$HOME_NET (기본)')}</td></tr>
    <tr><td>default-rule-path</td><td>${esc(c.yaml['default-rule-path'])}</td></tr>`;
  $('#cfg-yaml').innerHTML = `<div>설정파일: <b>${esc(c.paths.yaml)}</b></div>
    <div>로컬 룰: <b>${esc(c.paths.local_rules)}</b></div>
    <div>이벤트 로그: <b>${esc(c.paths.eve)}</b> · fast.log: <b>${esc(c.paths.fastlog)}</b></div>`;
  $('#cfg-rulesdir').innerHTML = `<div class="filelist">${(c.rules_dir || []).map(f => `<span>${esc(f)}</span>`).join('')}</div>`;
  $('#cfg-logdir').innerHTML = `<div class="filelist">${(c.log_dir || []).map(f => `<span>${esc(f)}</span>`).join('')}</div>`;
}

// analyzer
$('#an-sample').onclick = () => { $('#an-input').value = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"6V6 SQLi UNION"; flow:established,to_server; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000001; rev:2;)'; };
$('#an-btn').onclick = async () => {
  const r = await postJSON('/api/rule/analyze', { rule: $('#an-input').value });
  if (r.error) { $('#an-out').innerHTML = `<p class="result err">${esc(r.error)}</p>`; return; }
  const head = `<div class="an-head">
    <span class="an-chip">action <b>${esc(r.action)}</b></span>
    <span class="an-chip">proto <b>${esc(r.proto)}</b></span>
    <span class="an-chip">src <b>${esc(r.src)}</b>:${esc(r.sport)}</span>
    <span class="an-chip">dir <b>${esc(r.dir)}</b></span>
    <span class="an-chip">dst <b>${esc(r.dst)}</b>:${esc(r.dport)}</span></div>`;
  const desc = { msg: '사람이 읽는 설명', flow: '연결 방향/상태', 'http.uri': '요청 URL 버퍼', content: '찾을 문자열', nocase: '대소문자 무시', pcre: '정규식 매칭', sid: '룰 고유 ID', rev: '룰 버전', classtype: '공격 분류', threshold: '빈도 제한', distance: '직전 content 로부터 거리', within: '직전 content 이내', flags: 'TCP 플래그', 'http.user_agent': 'User-Agent 버퍼', 'dns.query': 'DNS 조회 버퍼' };
  const opts = (r.options || []).map(o => `<div class="an-opt"><span class="k">${esc(o.k)}</span><span class="v">${esc(o.v == null ? '(플래그)' : o.v)}</span><span class="note" style="margin:0">${esc(desc[o.k] || '')}</span></div>`).join('');
  $('#an-out').innerHTML = head + `<div class="panel" style="margin-top:8px"><div class="panel-h">옵션 ${r.options.length}개</div><div class="panel-b" style="padding:0">${opts}</div></div>`;
};

// rules
let lastRule = '';
function bindRuleForm() {
  $('#btn-preview').onclick = async () => {
    const r = await postJSON('/api/rule/preview', formData($('#rule-form')));
    if (r.rule) { lastRule = r.rule; $('#rule-cmd').textContent = r.rule; $('#btn-apply').disabled = false; }
    else { $('#rule-cmd').textContent = '오류: ' + (r.error || ''); $('#btn-apply').disabled = true; }
    $('#rule-result').innerHTML = '';
  };
  $('#btn-apply').onclick = async () => {
    const r = await postJSON('/api/rule/apply', { rule: lastRule });
    const cls = r.ok ? 'ok' : 'warn';
    $('#rule-result').innerHTML = `<span class="${cls}">${r.ok ? '✔' : '⚠'} ${esc(r.note || '')}</span> · reload=${esc(r.reload)} · loaded ${r.stats_after?.loaded}/failed ${r.stats_after?.failed}`;
    toast(r.ok ? '룰 적용 + reload 완료' : '룰 적용했으나 로딩 확인 필요');
    $('#btn-apply').disabled = true; loadRules(); loadStatus();
  };
}
async function loadRules() {
  const d = await getJSON('/api/rules');
  $('#rules-stats').textContent = `loaded ${d.stats.loaded} / failed ${d.stats.failed} · 다음 sid ${d.next_sid}`;
  const rows = (d.rules || []).map(r => `<div class="rrow">
    <span class="sid">${esc(r.sid || '?')}</span>
    <span class="msg">${esc(r.msg || r.raw.slice(0, 60))}</span>
    <span class="badge">${esc(r.proto)}/${esc(r.action)}</span>
    ${r.edu ? `<span class="del" data-sid="${esc(r.sid)}">삭제</span>` : '<span class="note" style="margin:0">시드</span>'}
  </div>`).join('');
  $('#rules-list').innerHTML = rows || '<p class="note">아직 룰이 없습니다.</p>';
  $$('.del', $('#rules-list')).forEach(b => b.onclick = async () => {
    if (!confirm('sid ' + b.dataset.sid + ' 룰 삭제?')) return;
    const r = await postJSON('/api/rule/delete', { sid: b.dataset.sid });
    toast(r.ok ? '삭제 + reload' : '삭제 실패: ' + (r.msg || '')); loadRules(); loadStatus();
  });
}

// eve
async function loadEve() {
  const f = $('#eve-filter').value;
  const d = await getJSON('/api/eve' + (f ? '?type=' + f : ''));
  $('#eve-counts').innerHTML = `<div class="cnt-grid">${Object.entries(d.counts || {}).map(([k, v]) => `<div class="c">${esc(k)} <b>${v}</b></div>`).join('') || '<span class="note">최근 이벤트 없음</span>'}</div>`;
  $('#eve-list').innerHTML = (d.events || []).map(e => {
    let detail = '';
    if (e.event_type === 'alert' && e.alert) detail = `<span class="sig">[${e.alert.sid}] ${esc(e.alert.signature || '')}</span> <span class="note" style="margin:0">${esc(e.alert.category || '')}</span>`;
    else if (e.event_type === 'http' && e.http) detail = `${esc(e.http.method || '')} ${esc(e.http.host || '')}${esc(e.http.url || '')} → ${esc(e.http.status || '')}`;
    else if (e.event_type === 'dns') detail = esc(e.dns || '');
    return `<div class="evrow"><span class="et ${esc(e.event_type)}">${esc(e.event_type)}</span>
      <span>${esc(e.ts)}</span><span>${esc(e.src_ip || '')}→${esc(e.dest_ip || '')}:${esc(e.dest_port || '')}</span>${detail}</div>`;
  }).join('') || '<p class="note">표시할 이벤트가 없습니다.</p>';
}
$('#eve-filter') && ($('#eve-filter').onchange = loadEve);

// siem
async function loadSiem() {
  const s = await getJSON('/api/siem');
  $('#siem-status').innerHTML = `<div><span class="dot ${s.integrated ? 'on' : 'off'}"></span> eve.json 연동: <b>${s.integrated ? '켜짐' : '꺼짐'}</b></div>
    <div><span class="dot ${s.agent_running ? 'on' : 'warn'}"></span> Wazuh 에이전트: <b>${s.agent_running ? '실행 중' : '확인 필요'}</b></div>
    <div><span class="dot on"></span> SIEM 매니저: <code>${esc(s.manager || '—')}</code></div>
    <div><span class="dot on"></span> 이벤트 로그: <code>${esc(s.event_log)}</code></div>`;
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
        <div class="evid" id="e-${esc(s.id)}"></div>
      </div></div>`).join('');
  $$('.scn-h').forEach(h => h.onclick = () => { const b = h.nextElementSibling; b.classList.toggle('open'); h.querySelector('.stx').textContent = b.classList.contains('open') ? '▴' : '▾'; });
  $$('.scn-check').forEach(btn => btn.onclick = async () => {
    const id = btn.dataset.id, v = $('#v-' + id), e = $('#e-' + id);
    v.textContent = '검증 중…'; v.className = 'scn-verdict';
    const r = await postJSON('/api/scenario/check', { id });
    v.textContent = r.ok ? '✔ 통과' : '✘ 미통과'; v.className = 'scn-verdict ' + (r.ok ? 'pass' : 'fail');
    e.textContent = (r.msg ? r.msg + '\n' : '') + (r.evidence ? JSON.stringify(r.evidence, null, 1) : '')
      + (r.stats ? '\nruleset: loaded ' + r.stats.loaded + ' / failed ' + r.stats.failed : '')
      + (!r.ok && r.hint ? '\n💡 ' + r.hint : '');
  });
}

$$('.nav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
$('#btn-refresh').onclick = () => { loadStatus(); switchView($('.nav-item.active').dataset.view); toast('새로고침'); };
bindRuleForm();
loadStatus();
setInterval(() => { if ($('.nav-item.active').dataset.view === 'dashboard') loadStatus(); }, 10000);
