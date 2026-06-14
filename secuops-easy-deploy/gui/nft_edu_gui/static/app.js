'use strict';
// nft_edu_gui frontend — vanilla JS, 의존성 없음.

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

async function getJSON(u) { const r = await fetch(u); return r.json(); }
async function postJSON(u, body) {
  const r = await fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}) });
  return r.json();
}
function toast(msg, ms = 2600) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add('hidden'), ms);
}
function formData(form) {
  const o = {}; new FormData(form).forEach((v, k) => { o[k] = v; });
  $$('input[type=checkbox]', form).forEach(c => { o[c.name] = c.checked; });
  return o;
}

const TITLES = { dashboard: '대시보드', interfaces: '인터페이스', rules: '룰 관리',
  objects: '객체 (그룹·Alias)', nat: 'NAT', conntrack: 'Stateful · 연결추적',
  activity: '로그 · 활동', siem: 'SIEM 연동', scenarios: '침해대응 훈련' };

function switchView(v) {
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  $$('.view').forEach(s => s.classList.toggle('hidden', s.id !== 'view-' + v));
  $('#view-title').textContent = TITLES[v] || v;
  const loaders = { interfaces: loadInterfaces, rules: loadRuleset, objects: loadObjects,
    nat: loadNat, conntrack: loadConntrack, activity: loadActivity, siem: loadSiem,
    scenarios: loadScenarios };
  if (loaders[v]) loaders[v]();
}

// ───────── status / dashboard ─────────
async function loadStatus() {
  const s = await getJSON('/api/status');
  $('#st-host').textContent = 'host ' + (s.hostname || '—');
  $('#st-nft').textContent = (s.nft_version || 'nft —').split(' ').slice(0, 2).join(' ');
  $('#st-rules').textContent = '룰 ' + (s.rule_count ?? '—');
  $('#st-ct').textContent = '연결 ' + (s.conntrack_count ?? '—');
  const cards = [
    ['호스트', s.hostname || '—', 'sm'],
    ['nftables', (s.nft_version || '').replace('nftables ', '') || '—', 'sm'],
    ['전체 룰 수', s.rule_count ?? '—', ''],
    ['활성 연결(conntrack)', s.conntrack_count ?? '—', ''],
    ['테이블', (s.tables || []).length, ''],
    ['인터페이스', (s.interfaces || []).filter(i => i.name !== 'lo').length, ''],
  ];
  $('#dash-cards').innerHTML = cards.map(([k, v, c]) =>
    `<div class="card"><div class="k">${esc(k)}</div><div class="v ${c}">${esc(v)}</div></div>`).join('');
}

async function loadInterfaces() {
  const s = await getJSON('/api/status');
  const rows = (s.interfaces || []).map(i =>
    `<tr><td>${esc(i.name)}</td><td>${esc((i.addrs || []).join(', '))}</td>
     <td>${esc(i.state)}</td><td>${esc(i.zone)}</td></tr>`).join('');
  $('#iface-tbl').innerHTML =
    `<tr><th>인터페이스</th><th>주소</th><th>상태</th><th>존(zone) · 역할</th></tr>${rows}`;
}

// ───────── ruleset ─────────
function ruleLine(r, withDel) {
  const m = (r.matchers || []).join(' ') || (r.action ? '' : 'all');
  const cnt = `<span class="cnt">pkts <b>${r.packets}</b> · ${r.bytes}B</span>`;
  const del = (withDel && r.editable && r.handle != null)
    ? `<span class="del" data-fam="${esc(r.family)}" data-tbl="${esc(r.table)}" data-chain="${esc(r.chain)}" data-handle="${r.handle}">삭제</span>` : '';
  const lg = r.log ? ` <span style="color:#fbbf24">${esc(r.log)}</span>` : '';
  return `<div class="rrow"><span class="matchers">${esc(m)}</span>${lg}
    <span class="act ${esc((r.action || '').split(' ')[0])}">${esc(r.action || '')}</span>${cnt}${del}</div>`;
}
function renderTables(tables, target, onlyTable, withDel) {
  const host = $(target); let html = '';
  (tables || []).forEach(t => {
    if (onlyTable && t.name !== onlyTable) return;
    t.chains.forEach(c => {
      html += `<div class="chain-block"><div class="chain-head">
        <b>${esc(t.family)} ${esc(t.name)}</b> · ${esc(c.name)}
        ${c.hook ? `<span style="color:#60a5fa">hook ${esc(c.hook)}</span>` : ''}
        ${c.policy ? `<span class="pol">policy ${esc(c.policy)}</span>` : ''}
        <span class="ed ${t.editable ? 'yes' : 'no'}">${t.editable ? '편집가능' : '읽기전용'}</span></div>`;
      if (!c.rules.length) html += `<div class="rrow"><span class="cnt">(룰 없음)</span></div>`;
      c.rules.forEach(r => { html += ruleLine(r, withDel); });
      html += `</div>`;
    });
  });
  host.innerHTML = html || '<p class="note">룰이 없습니다.</p>';
  if (withDel) $$('.del', host).forEach(d => d.onclick = () => delRule(d.dataset));
}
async function loadRuleset() {
  const m = await getJSON('/api/ruleset');
  if (m.error) { $('#ruleset-view').innerHTML = `<p class="result err">${esc(m.error)}</p>`; return; }
  renderTables(m.tables, '#ruleset-view', null, true);
}
async function delRule(d) {
  if (!confirm(`룰 삭제: ${d.fam} ${d.tbl} ${d.chain} handle ${d.handle} ?`)) return;
  const r = await postJSON('/api/rule/delete', { family: d.fam, table: d.tbl, chain: d.chain, handle: +d.handle });
  if (r.ok) { toast('룰 삭제됨'); loadRuleset(); loadStatus(); }
  else toast('삭제 실패: ' + (r.error || r.result?.stderr || ''));
}

// rule form
function bindRuleForm() {
  const form = $('#rule-form'), cmdbox = $('#rule-cmd'), applyBtn = $('#btn-apply');
  let lastCmd = '';
  $('#btn-preview').onclick = async () => {
    const r = await postJSON('/api/rule/preview', formData(form));
    if (r.command) { lastCmd = r.command; cmdbox.textContent = r.command; applyBtn.disabled = false; }
    else { cmdbox.textContent = '오류: ' + (r.error || '입력 확인'); applyBtn.disabled = true; }
    $('#rule-result').innerHTML = '';
  };
  applyBtn.onclick = async () => {
    if (!lastCmd) return;
    const r = await postJSON('/api/rule/apply', { command: lastCmd });
    if (r.ok) { $('#rule-result').innerHTML = `<span class="ok">✔ 적용됨</span>`; toast('룰 적용됨'); loadStatus(); }
    else $('#rule-result').innerHTML = `<span class="err">✘ ${esc(r.error || r.result?.stderr || '실패')}</span>`;
    if (r.ruleset) renderTables(r.ruleset.tables, '#ruleset-view', null, true);
    applyBtn.disabled = true;
  };
  $('#reset-counters').onclick = resetCounters;
}
async function resetCounters() {
  const r = await postJSON('/api/counters/reset', {});
  toast(r.ok ? '카운터 리셋됨' : '리셋 실패'); loadRuleset(); loadActivity();
}

// ───────── objects (named sets / alias / group) ─────────
let lastObjCmds = null;
function bindObjForm() {
  const form = $('#obj-form');
  $('#obj-preview').onclick = async () => {
    const r = await postJSON('/api/object/preview', formData(form));
    if (r.commands) { lastObjCmds = r; $('#obj-cmd').textContent = r.commands; $('#obj-apply').disabled = false; }
    else { $('#obj-cmd').textContent = '오류: ' + (r.error || ''); $('#obj-apply').disabled = true; }
    $('#obj-result').innerHTML = '';
  };
  $('#obj-apply').onclick = async () => {
    if (!lastObjCmds) return;
    const r = await postJSON('/api/object/apply', { create: lastObjCmds.create, element: lastObjCmds.element });
    $('#obj-result').innerHTML = r.ok ? `<span class="ok">✔ 그룹 생성됨</span>`
      : `<span class="err">✘ ${esc(r.error || '')}</span>`;
    if (r.ok) { toast('객체(그룹) 생성됨'); }
    $('#obj-apply').disabled = true; loadObjects();
  };
}
async function loadObjects() {
  const d = await getJSON('/api/objects');
  const objs = d.objects || [];
  $('#obj-list').innerHTML = objs.map(o => `
    <div class="chain-block">
      <div class="chain-head"><b>@${esc(o.name)}</b>
        <span style="color:#60a5fa">${esc(o.type_label || o.type)}</span>
        <span class="del" data-del="${esc(o.name)}" style="margin-left:auto">그룹 삭제</span></div>
      <div class="rrow"><span class="matchers">${(o.elements || []).map(e => `<code>${esc(e)}</code>`).join(' ') || '<span class="cnt">(빈 그룹)</span>'}</span></div>
      <div class="rrow">
        <input class="obj-el" data-name="${esc(o.name)}" placeholder="구성원 (쉼표 구분)"
          style="flex:1;background:#0a0e13;border:1px solid #1e2733;border-radius:6px;padding:6px 9px;color:#d7e0ea;font-family:inherit;font-size:12px">
        <span class="del" data-add="${esc(o.name)}" style="color:#34d399;border-color:#0e2a18">+ 추가</span>
        <span class="del" data-rm="${esc(o.name)}">− 삭제</span>
      </div>
    </div>`).join('') || '<p class="note">아직 만든 그룹이 없습니다. 왼쪽에서 만들어 보세요.</p>';
  const host = $('#obj-list');
  $$('.del[data-del]', host).forEach(b => b.onclick = async () => {
    if (!confirm('그룹 @' + b.dataset.del + ' 삭제? (이 그룹을 쓰는 룰이 있으면 먼저 룰을 지워야 함)')) return;
    const r = await postJSON('/api/object/delete', { name: b.dataset.del });
    toast(r.ok ? '그룹 삭제됨' : (r.error || '삭제 실패')); loadObjects();
  });
  const elemAction = async (name, action) => {
    const inp = host.querySelector('.obj-el[data-name="' + name + '"]');
    const els = inp ? inp.value.trim() : '';
    if (!els) { toast('구성원을 입력하세요'); return; }
    const r = await postJSON('/api/object/element', { name, elements: els, action });
    toast(r.ok ? (action === 'add' ? '구성원 추가됨' : '구성원 삭제됨') : (r.result?.stderr || '실패')); loadObjects();
  };
  $$('.del[data-add]', host).forEach(b => b.onclick = () => elemAction(b.dataset.add, 'add'));
  $$('.del[data-rm]', host).forEach(b => b.onclick = () => elemAction(b.dataset.rm, 'delete'));
}

// ───────── NAT ─────────
function bindNatForm() {
  const form = $('#nat-form'), cmdbox = $('#nat-cmd'), applyBtn = $('#nat-apply');
  let lastCmd = '';
  form.kind.onchange = () => {
    const isD = form.kind.value === 'dnat';
    $('.dnat-only').classList.toggle('hidden', !isD);
    $('.snat-only').classList.toggle('hidden', isD);
  };
  $('#nat-preview').onclick = async () => {
    const d = formData(form);
    if (d.kind === 'snat') d.to_ip = d.snat_ip;
    const r = await postJSON('/api/nat/preview', d);
    if (r.command) { lastCmd = r.command; cmdbox.textContent = r.command; applyBtn.disabled = false; }
    else { cmdbox.textContent = '오류: ' + (r.error || ''); applyBtn.disabled = true; }
  };
  applyBtn.onclick = async () => {
    const r = await postJSON('/api/nat/apply', { command: lastCmd });
    $('#nat-result').innerHTML = r.ok ? `<span class="ok">✔ 적용됨</span>`
      : `<span class="err">✘ ${esc(r.error || r.result?.stderr || '')}</span>`;
    if (r.ok) { toast('NAT 적용됨'); loadNat(); loadStatus(); }
    applyBtn.disabled = true;
  };
}
async function loadNat() {
  const m = await getJSON('/api/ruleset');
  renderTables(m.tables, '#nat-view', 'six_nat', true);
}

// ───────── conntrack ─────────
async function loadConntrack() {
  const c = await getJSON('/api/conntrack');
  $('#ct-count').textContent = (c.count ?? 0) + ' 연결';
  const rows = (c.conns || []).map(x =>
    `<tr><td>${esc(x.proto)}</td><td>${esc(x.state || '')}</td>
     <td>${esc(x.src)}:${esc(x.sport || '')}</td><td>${esc(x.dst)}:${esc(x.dport || '')}</td>
     <td>${x.assured ? '✔' : ''}${x.unreplied ? ' (unreplied)' : ''}</td></tr>`).join('');
  $('#ct-tbl').innerHTML = `<tr><th>proto</th><th>state</th><th>출발</th><th>목적</th><th>assured</th></tr>`
    + (rows || `<tr><td colspan=5 class="cnt">활성 연결 없음</td></tr>`);
}

// ───────── activity ─────────
async function loadActivity() {
  const m = await getJSON('/api/ruleset');
  const rows = [];
  (m.tables || []).forEach(t => t.chains.forEach(c => c.rules.forEach(r => {
    if (r.packets > 0 || r.editable) rows.push(
      `<tr><td>${esc(t.name)}/${esc(c.name)}</td><td>${esc((r.matchers || []).join(' '))} <b>${esc(r.action || '')}</b></td>
       <td style="color:${r.packets > 0 ? '#22d3ee' : '#8a98a8'}">${r.packets}</td><td>${r.bytes}</td></tr>`);
  })));
  $('#counter-view').innerHTML = `<table class="tbl"><tr><th>체인</th><th>룰</th><th>packets</th><th>bytes</th></tr>${rows.join('')}</table>`;
  $('#act-reset').onclick = resetCounters;
  const ev = await getJSON('/api/events');
  const evrows = (ev.events || []).slice().reverse().map(e =>
    `<tr><td>${esc(e.ts || '')}</td><td>${esc(e.action || '')}</td><td class="mono">${esc(e.command || e.detail || e.raw || '')}</td></tr>`).join('');
  $('#event-view').innerHTML = evrows
    ? `<table class="tbl"><tr><th>시각</th><th>동작</th><th>내용</th></tr>${evrows}</table>`
    : `<p class="note">아직 이벤트가 없습니다. 룰을 적용하면 여기에 기록됩니다.</p>`;
}

// ───────── SIEM ─────────
async function loadSiem() {
  const s = await getJSON('/api/siem');
  $('#siem-status').innerHTML =
    `<div><span class="dot ${s.integrated ? 'on' : 'off'}"></span> 연동 상태: <b>${s.integrated ? '켜짐 (Wazuh 가 이벤트 로그 감시 중)' : '꺼짐'}</b></div>
     <div><span class="dot ${s.agent_running ? 'on' : 'warn'}"></span> Wazuh 에이전트: <b>${s.agent_running ? '실행 중' : '확인 필요'}</b></div>
     <div><span class="dot on"></span> SIEM 매니저: <code>${esc(s.manager || '—')}</code></div>
     <div><span class="dot on"></span> 이벤트 로그: <code>${esc(s.event_log)}</code></div>`;
  $('#siem-detail').textContent = (s.status_raw || '').trim();
  $('#siem-enable').onclick = async () => { const r = await postJSON('/api/siem/enable', {}); toast(r.msg || ''); loadSiem(); };
  $('#siem-disable').onclick = async () => { const r = await postJSON('/api/siem/disable', {}); toast(r.msg || ''); loadSiem(); };
}

// ───────── scenarios ─────────
async function loadScenarios() {
  const d = await getJSON('/api/scenarios');
  $('#scn-intro').textContent = d.intro || '';
  $('#scn-list').innerHTML = (d.scenarios || []).map(s => `
    <div class="scn" data-id="${esc(s.id)}">
      <div class="scn-h"><span class="lv">${esc(s.level || '')}</span>
        <span class="id">${esc(s.id)}</span><span class="ti">${esc(s.title)}</span>
        <span class="stx">▾</span></div>
      <div class="scn-b">
        <h5>상황</h5><p>${esc(s.situation)}</p>
        <h5>공격 재현</h5><div class="codeln">${esc(s.attack)}</div>
        <h5>해야 할 일</h5><p>${esc(s.task)}</p>
        <h5>GUI 입력값</h5><p class="build">${esc(s.build)}</p>
        <h5>힌트</h5><p class="note">${esc(s.hint)}</p>
        <h5>배우는 개념</h5><p class="note">${esc(s.learn)}</p>
        <div class="scn-actions">
          <button class="btn btn-primary scn-check" data-id="${esc(s.id)}">검증</button>
          <span class="scn-verdict" id="v-${esc(s.id)}"></span>
        </div>
        <div class="evid" id="e-${esc(s.id)}"></div>
      </div>
    </div>`).join('');
  $$('.scn-h').forEach(h => h.onclick = () => {
    const b = h.nextElementSibling; b.classList.toggle('open');
    h.querySelector('.stx').textContent = b.classList.contains('open') ? '▴' : '▾';
  });
  $$('.scn-check').forEach(btn => btn.onclick = async () => {
    const id = btn.dataset.id, v = $('#v-' + id), e = $('#e-' + id);
    v.textContent = '검증 중…'; v.className = 'scn-verdict';
    const r = await postJSON('/api/scenario/check', { id });
    v.textContent = r.ok ? '✔ 통과' : '✘ 미통과';
    v.className = 'scn-verdict ' + (r.ok ? 'pass' : 'fail');
    e.textContent = (r.msg ? r.msg + '\n' : '') + (r.evidence ? JSON.stringify(r.evidence, null, 1) : '')
      + (!r.ok && r.hint ? '\n💡 ' + r.hint : '');
  });
}

// ───────── boot ─────────
$$('.nav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
$('#btn-refresh').onclick = () => { loadStatus(); const v = $('.nav-item.active').dataset.view;
  switchView(v); toast('새로고침'); };
bindRuleForm(); bindNatForm(); bindObjForm();
loadStatus();
setInterval(() => { if ($('.nav-item.active').dataset.view === 'dashboard') loadStatus(); }, 8000);
