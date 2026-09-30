/* RSAttax — UI controller. Talks to worker.js (Pyodide) for all crypto. */

const ATTACKS = [
  { id: "fermat", no: 1, title: "Fermat Factorization", pre: "p, q <b>berdekatan</b> (|p−q| kecil)" },
  { id: "ecm", no: 2, title: "Elliptic Curve Method", pre: "faktor prima <b>ukuran sedang</b> (Lenstra ECM)" },
  { id: "small_e", no: 3, title: "Small Public Exponent", pre: "e kecil (3) & <b>tanpa padding</b> (mᵉ < n)" },
  { id: "common_modulus", no: 4, title: "Common Modulus", pre: "n sama untuk 2 penerima, <b>gcd(e₁,e₂)=1</b>" },
  { id: "hastad", no: 5, title: "Håstad Broadcast", pre: "pesan sama ke <b>≥ e penerima</b>, e kecil" },
  { id: "franklin_reiter", no: 6, title: "Franklin-Reiter", pre: "dua pesan <b>berelasi linier</b>, e kecil" },
  { id: "partial_p", no: 8, title: "Partial Key Exposure", pre: "sebagian <b>bit p bocor</b> (Coppersmith)" },
  { id: "small_d", no: 10, title: "Small Private Exponent", pre: "d <b>sangat kecil</b> (brute-force)" },
  { id: "wiener", no: 11, title: "Wiener's Attack", pre: "d < <b>⅓·N^¼</b> (pecahan kontinu)" },
  { id: "pollard_p1", no: 13, title: "Pollard's p−1", pre: "<b>p−1 halus</b> (B-smooth)" },
  { id: "blind_signature", no: 16, title: "Blind Signature", pre: "akses <b>oracle dekripsi</b> (malleable)" },
  { id: "stereotyped", no: 19, title: "Stereotyped Message", pre: "<b>mayoritas plaintext diketahui</b>, e kecil" },
];

const REPO_URL = "https://github.com/DSKPutra/rsattax";

const grid = document.getElementById("grid");
const statusPill = document.getElementById("status-pill");
const statusText = document.getElementById("status-text");
const statusDot = statusPill.querySelector(".dot");
const runAllBtn = document.getElementById("run-all");
const msgInput = document.getElementById("msg");
document.getElementById("repo-link").href = REPO_URL;

// ---- build cards
const cards = {};
for (const a of ATTACKS) {
  const el = document.createElement("article");
  el.className = "card";
  el.innerHTML = `
    <div class="card-head">
      <div>
        <div class="card-num">ATTACK #${a.no}</div>
        <h3 class="card-title">${a.title}</h3>
      </div>
      <span class="badge idle" data-badge>idle</span>
    </div>
    <div class="card-pre">${a.pre}</div>
    <div class="card-foot">
      <button class="run" data-run disabled>▶ Jalankan</button>
    </div>
    <div class="result" data-result></div>`;
  grid.appendChild(el);
  cards[a.id] = el;
  el.querySelector("[data-run]").addEventListener("click", () => runOne(a.id));
}

// ---- worker plumbing
const worker = new Worker("worker.js");
let seq = 0;
const pending = new Map();
let workerReady = false;

worker.onmessage = (e) => {
  const m = e.data;
  if (m.type === "ready") {
    workerReady = true;
    statusDot.className = "dot";
    statusText.textContent = "Runtime siap — WebAssembly aktif";
    runAllBtn.disabled = false;
    document.querySelectorAll("[data-run]").forEach((b) => (b.disabled = false));
    isoRunBtn.disabled = false;
    isoValidateBtn.disabled = false;
  } else if (m.type === "fatal") {
    statusDot.className = "dot err";
    statusText.textContent = "Gagal memuat runtime: " + m.error;
  } else if (m.type === "result") {
    const cb = pending.get(m.id);
    if (cb) { pending.delete(m.id); cb(m.data); }
  }
};

function callWorker(payload) {
  return new Promise((resolve) => {
    const id = ++seq;
    pending.set(id, resolve);
    worker.postMessage({ id, ...payload });
  });
}

// ---- run logic
function setBadge(id, kind, text) {
  const b = cards[id].querySelector("[data-badge]");
  b.className = "badge " + kind;
  b.textContent = text;
}

function renderResult(id, r) {
  const card = cards[id];
  const box = card.querySelector("[data-result]");
  const ok = !!r.success;
  card.classList.remove("running");
  card.classList.toggle("ok", ok);
  card.classList.toggle("bad", !ok);
  setBadge(id, ok ? "ok" : "bad", ok ? `✓ ${r.time_s ?? "?"}s` : "✗ gagal");
  const pub = r.public || {};
  const pubRows = Object.entries(pub)
    .map(([k, v]) => `<div class="row"><span class="k">${k}</span><span class="v">${v}</span></div>`)
    .join("");
  box.innerHTML = `
    <div class="row"><span class="k">recovered</span><span class="v rec ${ok ? "" : "bad"}">${escapeHtml(String(r.recovered))}</span></div>
    ${r.extra ? `<div class="row"><span class="k">param</span><span class="v">${escapeHtml(r.extra)}</span></div>` : ""}
    ${pubRows}
    <div class="method">↳ ${escapeHtml(r.method || "")}</div>`;
  box.classList.add("show");
}

async function runOne(id) {
  if (!workerReady) return;
  const msg = (msgInput.value || "RSAttax").slice(0, 40);
  const card = cards[id];
  card.classList.remove("ok", "bad");
  card.classList.add("running");
  setBadge(id, "run", "⏳ running…");
  card.querySelector("[data-run]").disabled = true;
  const r = await callWorker({ aid: id, msg });
  renderResult(id, r);
  card.querySelector("[data-run]").disabled = false;
  return r;
}

async function runAll() {
  runAllBtn.disabled = true;
  runAllBtn.textContent = "⏳ menjalankan…";
  document.querySelectorAll("[data-run]").forEach((b) => (b.disabled = true));
  let ok = 0;
  for (const a of ATTACKS) {
    const r = await runOne(a.id);
    if (r && r.success) ok++;
    runAllBtn.textContent = `⏳ ${ok}/${ATTACKS.length} berhasil…`;
  }
  document.querySelectorAll("[data-run]").forEach((b) => (b.disabled = false));
  runAllBtn.disabled = false;
  runAllBtn.textContent = `▶ Jalankan semua (${ok}/${ATTACKS.length} ✓)`;
}
runAllBtn.addEventListener("click", runAll);

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

// ---- ISO/IEC conformance lab
const isoRunBtn = document.getElementById("iso-run");
const isoValidateBtn = document.getElementById("iso-validate");
const isoSelftestBox = document.getElementById("iso-selftest-result");
const isoValidateBox = document.getElementById("iso-validate-result");

function renderGroups(groups) {
  return groups
    .map((g) => {
      const checks = g.checks
        .map(
          (c) => `<div class="iso-check">
            <span class="mark ${c.ok ? "y" : "n"}">${c.ok ? "✓" : "✗"}</span>
            <span class="lab">${escapeHtml(c.label)}</span>
            <span class="val">${escapeHtml(c.value)}</span></div>`
        )
        .join("");
      return `<div class="iso-group">
        <div class="iso-group-head">
          <span class="std">${escapeHtml(g.std)}</span>
          <span class="gname">${escapeHtml(g.name)}</span>
          <span class="gp ${g.pass ? "y" : "n"}">${g.pass ? "PASS" : "FAIL"}</span>
        </div>${checks}</div>`;
    })
    .join("");
}

isoRunBtn.addEventListener("click", async () => {
  if (!workerReady) return;
  isoRunBtn.disabled = true;
  isoRunBtn.textContent = "⏳ menjalankan…";
  isoSelftestBox.classList.add("show");
  isoSelftestBox.innerHTML = '<div class="iso-summary">menghitung…</div>';
  const r = await callWorker({ cmd: "iso_selftest" });
  const allok = r.passed === r.total;
  isoSelftestBox.innerHTML =
    `<div class="iso-summary ${allok ? "ok" : "bad"}">${allok ? "✓" : "✗"} ${r.passed}/${r.total} kelompok uji lulus</div>` +
    renderGroups(r.groups);
  isoRunBtn.disabled = false;
  isoRunBtn.textContent = "▶ Jalankan ulang self-test";
});

isoValidateBtn.addEventListener("click", async () => {
  if (!workerReady) return;
  const n = document.getElementById("iso-n").value.trim();
  const exp = document.getElementById("iso-e").value.trim() || "65537";
  if (!n) {
    isoValidateBox.classList.add("show");
    isoValidateBox.innerHTML = '<div class="iso-summary bad">✗ masukkan modulus n dulu</div>';
    return;
  }
  isoValidateBtn.disabled = true;
  isoValidateBtn.textContent = "⏳…";
  isoValidateBox.classList.add("show");
  isoValidateBox.innerHTML = '<div class="iso-summary">memvalidasi…</div>';
  const r = await callWorker({ cmd: "iso_validate", n, exp });
  if (r.error) {
    isoValidateBox.innerHTML = `<div class="iso-summary bad">✗ ${escapeHtml(r.error)}</div>`;
  } else {
    isoValidateBox.innerHTML =
      `<div class="iso-summary ${r.pass ? "ok" : "bad"}">${r.pass ? "✓ LULUS" : "✗ TIDAK LULUS"} · modulus ${r.modulus_bits}-bit</div>` +
      renderGroups([{ std: "ISO/IEC 18033-2", name: "Validasi kunci publik RSA", checks: r.checks, pass: r.pass }]);
  }
  isoValidateBtn.disabled = false;
  isoValidateBtn.textContent = "Validasi";
});
