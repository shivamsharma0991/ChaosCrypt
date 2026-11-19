const $ = (id) => document.getElementById(id);
let lastPackage = null;      // Blob of the most recent .enc
let lastPkgName = "encrypted.enc";
let lastDecDataUrl = null;
let imgFile = null, pkgFile = null;

function show(el, on = true) { el.hidden = !on; }
function showError(id, msg) { const e = $(id); e.textContent = msg; show(e, !!msg); }
function download(blob, name) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function b64ToBlob(b64, type) {
  const bin = atob(b64), arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return new Blob([arr], { type });
}
async function post(url, form) {
  const r = await fetch(url, { method: "POST", body: form });
  let data = {};
  try { data = await r.json(); } catch { /* non-JSON error */ }
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}
function busy(btn, on, label) {
  btn.disabled = on;
  if (on) { btn.dataset.label = btn.textContent; btn.textContent = label; }
  else btn.textContent = btn.dataset.label || btn.textContent;
}
function fmtBytes(n) { return n > 1048576 ? (n / 1048576).toFixed(2) + " MB" : (n / 1024).toFixed(1) + " KB"; }

// tabs
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
  show($("tab-enc"), t.dataset.tab === "enc");
  show($("tab-dec"), t.dataset.tab === "dec");
}));

// keys
$("genKeys").addEventListener("click", async (e) => {
  busy(e.target, true, "Generating...");
  try {
    const d = await post("/api/keys", new FormData());
    $("pubKey").value = d.public_key; $("privKey").value = d.private_key;
  } catch (err) { showError("encErr", err.message); }
  busy(e.target, false);
});
document.querySelectorAll("[data-dl]").forEach((b) => b.addEventListener("click", (e) => {
  e.preventDefault();
  const v = $(b.dataset.dl).value.trim();
  if (v) download(new Blob([v + "\n"], { type: "text/plain" }), b.dataset.name);
}));

// drop zones
function wireDrop(zoneId, inputId, textId, onFile) {
  const z = $(zoneId), inp = $(inputId);
  const set = (f) => { if (f) { $(textId).textContent = f.name; onFile(f); } };
  inp.addEventListener("change", () => set(inp.files[0]));
  ["dragenter", "dragover"].forEach((ev) => z.addEventListener(ev, (e) => { e.preventDefault(); z.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => z.addEventListener(ev, (e) => { e.preventDefault(); z.classList.remove("over"); }));
  z.addEventListener("drop", (e) => set(e.dataTransfer.files[0]));
}
wireDrop("dropEnc", "imgFile", "dropEncText", (f) => { imgFile = f; });
wireDrop("dropDec", "pkgFile", "dropDecText", (f) => { pkgFile = f; });

// encrypt
$("encBtn").addEventListener("click", async (e) => {
  showError("encErr", "");
  if (!imgFile) return showError("encErr", "Please choose an image first.");
  busy(e.target, true, "Encrypting...");
  if (!$("pubKey").value.trim()) {
    try {
      const k = await post("/api/keys", new FormData());
      $("pubKey").value = k.public_key; $("privKey").value = k.private_key;
    } catch (err) { busy(e.target, false); return showError("encErr", err.message); }
  }
  const fd = new FormData();
  fd.append("image", imgFile);
  fd.append("public_key", $("pubKey").value);
  fd.append("analyze", $("analyze").checked ? "true" : "false");
  try {
    const d = await post("/api/encrypt", fd);
    $("origImg").src = URL.createObjectURL(imgFile);
    $("encImg").src = d.encrypted_preview;
    lastPackage = b64ToBlob(d.package, "application/octet-stream");
    lastPkgName = imgFile.name.replace(/\.[^.]+$/, "") + ".enc";
    $("encInfo").textContent = `${d.width}x${d.height}, ${d.channels} ch, ${d.time_ms} ms, package ${fmtBytes(d.package_bytes)}`;
    renderMetrics(d.metrics);
    show($("encOut"));
  } catch (err) { showError("encErr", err.message); show($("encOut"), false); }
  busy(e.target, false);
});

function renderMetrics(m) {
  const box = $("metrics"); box.innerHTML = "";
  if (!m) return;
  const items = [
    [m.entropy_cipher.toFixed(4), "Cipher entropy (ideal 8)"],
    [m.entropy_plain.toFixed(4), "Plain entropy"],
    [m.corr_cipher.horizontal.toFixed(4), "Cipher correlation, horizontal"],
    [m.corr_plain.horizontal.toFixed(4), "Plain correlation, horizontal"],
    [m.npcr.toFixed(4) + "%", "NPCR (1-pixel change)"],
    [m.uaci.toFixed(2) + "%", "UACI (1-pixel change)"],
  ];
  for (const [v, l] of items) {
    const d = document.createElement("div"); d.className = "metric";
    d.innerHTML = `<b>${v}</b><span>${l}</span>`; box.appendChild(d);
  }
}

$("dlPkg").addEventListener("click", () => lastPackage && download(lastPackage, lastPkgName));
$("toDec").addEventListener("click", () => {
  if (!lastPackage) return;
  pkgFile = new File([lastPackage], lastPkgName);
  $("dropDecText").textContent = lastPkgName + " (from Encrypt tab)";
  document.querySelector('[data-tab="dec"]').click();
});

// decrypt
$("decBtn").addEventListener("click", async (e) => {
  showError("decErr", "");
  if (!pkgFile) return showError("decErr", "Please choose an .enc package.");
  if (!$("privKey").value.trim()) return showError("decErr", "Paste or generate the private key first.");
  const fd = new FormData();
  fd.append("package", pkgFile);
  fd.append("private_key", $("privKey").value);
  fd.append("allow_corrupt", $("allowCorrupt").checked ? "true" : "false");
  busy(e.target, true, "Decrypting...");
  try {
    const d = await post("/api/decrypt", fd);
    lastDecDataUrl = d.image;
    $("decImg").src = d.image;
    $("badges").innerHTML =
      `<span class="badge ${d.integrity_ok ? "ok" : "bad"}">${d.integrity_ok ? "Integrity verified" : "Integrity check failed"}</span>` +
      `<span class="badge ${d.bit_exact ? "ok" : "bad"}">${d.bit_exact ? "Bit-exact match with original" : "Not identical to original"}</span>`;
    $("decInfo").textContent = `${d.width}x${d.height}, ${d.channels} ch, ${d.time_ms} ms`;
    show($("decOut"));
  } catch (err) { showError("decErr", err.message); show($("decOut"), false); }
  busy(e.target, false);
});
$("dlImg").addEventListener("click", () => {
  if (!lastDecDataUrl) return;
  const a = document.createElement("a"); a.href = lastDecDataUrl; a.download = "decrypted.png"; a.click();
});
