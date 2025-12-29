/* Minimal SPA för MVP. Inga externa deps. */

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, children = []) => {
  const n = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else n.setAttribute(k, v);
  });
  children.forEach((c) => n.appendChild(c));
  return n;
};

function b64(s) {
  return btoa(unescape(encodeURIComponent(s)));
}

function getCreds() {
  const user = localStorage.getItem("admin_user") || "";
  const pass = localStorage.getItem("admin_pass") || "";
  return { user, pass };
}

function setCreds(user, pass) {
  localStorage.setItem("admin_user", user);
  localStorage.setItem("admin_pass", pass);
}

async function api(path, { method = "GET", jsonBody, admin = false, multipart } = {}) {
  const headers = {};
  if (jsonBody) headers["Content-Type"] = "application/json";
  if (admin) {
    const { user, pass } = getCreds();
    headers["Authorization"] = "Basic " + b64(`${user}:${pass}`);
  }
  const res = await fetch(path, {
    method,
    headers,
    body: multipart ? multipart : (jsonBody ? JSON.stringify(jsonBody) : undefined),
  });
  const ct = res.headers.get("content-type") || "";
  const isJson = ct.includes("application/json");
  const body = isJson ? await res.json().catch(() => null) : await res.text().catch(() => "");
  if (!res.ok) {
    // Om admin-auth fallerar: växla UI tillbaka till login-rutan
    // (men bara för /api/admin/* så vi inte råkar gömma admin p.g.a. andra 401:or).
    if (res.status === 401 && String(path).startsWith("/api/admin/")) {
      setAdminAuthed(false);
      showToast("Inte inloggad (fel användarnamn/lösenord).");
    }
    const err = body && body.error ? body.error : `HTTP ${res.status}`;
    const details = body && body.details ? body.details : body;
    throw new Error(`${err}${details ? " :: " + JSON.stringify(details) : ""}`);
  }
  return body;
}

function showView(name) {
  $("#view-admin").classList.toggle("active", name === "admin");
  $("#view-quiz").classList.toggle("active", name === "quiz");
  $("#tab-admin").classList.toggle("active", name === "admin");
  $("#tab-quiz").classList.toggle("active", name === "quiz");
}

function viewFromPath(pathname) {
  const p = (pathname || "/").toLowerCase();
  if (p.startsWith("/admin")) return "admin";
  if (p.startsWith("/quiz")) return "quiz";
  // Default: quiz (trevligare för användare som bara vill spela)
  return "quiz";
}

function navigateTo(view) {
  const target = view === "admin" ? "/admin" : "/quiz";
  if (location.pathname !== target) history.pushState({ view }, "", target);
  showView(view);
  if (view === "admin") checkAdminAuthAndGate();
  else showLoginModal(false);
}

function setAdminAuthed(ok) {
  const adminOnly = document.querySelector("#admin-only");
  if (adminOnly) adminOnly.style.display = ok ? "" : "none";
  const logout = document.querySelector("#logout-btn");
  if (logout) logout.style.display = ok ? "" : "none";
  if (viewFromPath(location.pathname) === "admin") {
    showLoginModal(!ok);
  }
}

function showLoginModal(show) {
  const m = document.querySelector("#login-modal");
  if (!m) return;
  m.style.display = show ? "" : "none";
  m.setAttribute("aria-hidden", show ? "false" : "true");
  if (show) {
    try { $("#login-user")?.focus(); } catch {}
  }
}

async function checkAdminAuthAndGate() {
  // Default: göm admin-innehåll tills vi lyckats auth:a
  setAdminAuthed(false);
  const { user, pass } = getCreds();
  if (!user || !pass) {
    const u = document.querySelector("#login-user");
    const p = document.querySelector("#login-pass");
    if (u) u.value = user || "";
    if (p) p.value = pass || "";
    return;
  }
  try {
    await api("/api/admin/ping", { admin: true });
    setAdminAuthed(true);
  } catch {
    setAdminAuthed(false);
    showToast("Logga in för att använda admin.");
  }
}

let state = {
  sets: [],
  adminSetId: null,
  adminMeta: null,
  standDraftXY: null,
  selectedStandId: null,
  quiz: {
    pack: null,
    idx: 0,
    current: null,
    attempts: 0,
    mistakesTotal: 0,
    mistakesByQuestion: {}, // standId -> mistakes (capped)
    dotStates: {}, // standId -> "correct1" | "correct2" | "correct3" | "reveal"
    labelsPersistent: {}, // standId -> name
    standNameById: {}, // standId -> name (från set-meta)
    meta: null,
    revealActive: false,
    revealId: null,
    mode: "rand10",
    selectedSetId: null,
  },
};

function fmt(x) {
  return JSON.stringify(x, null, 2);
}

function getOrCreateToast() {
  let t = document.querySelector("#toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    t.className = "toast";
    document.body.appendChild(t);
  }
  return t;
}

let toastTimer = null;
function showToast(msg, ms = 3500) {
  const t = getOrCreateToast();
  t.textContent = msg;
  t.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    try { t.classList.remove("show"); } catch {}
  }, ms);
}

function updateScore() {
  const total = (state.quiz.pack?.questions || []).length || 0;
  const mistakes = state.quiz.mistakesTotal || 0;
  const pct = total > 0 ? Math.round((100 * total) / (total + mistakes)) : 100;
  $("#quiz-score").textContent = `${pct}%`;
  return pct;
}

function clamp01(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.max(0, Math.min(1, n));
}

function normClick(imgEl, evt) {
  const r = imgEl.getBoundingClientRect();
  if (!r || r.width <= 0 || r.height <= 0) return { x: null, y: null };
  const x = (evt.clientX - r.left) / r.width;
  const y = (evt.clientY - r.top) / r.height;
  return { x: clamp01(x), y: clamp01(y) };
}

function renderMap(container, meta, { onClick, dots, polygons, labels } = {}) {
  container.innerHTML = "";
  if (!meta || !meta.imageUrl) {
    container.appendChild(el("div", { class: "hint", text: "Ingen bild uppladdad ännu." }));
    return;
  }
  const img = el("img", { src: meta.imageUrl, alt: meta.set?.name || "karta" });
  container.appendChild(img);

  const overlay = el("svg", { class: "overlay", viewBox: "0 0 1000 1000", preserveAspectRatio: "none" });
  overlay.style.position = "absolute";
  overlay.style.inset = "0";
  overlay.style.width = "100%";
  overlay.style.height = "100%";
  container.appendChild(overlay);

  if (polygons && polygons.length) {
    polygons.forEach((poly) => {
      const pts = poly.map((p) => `${p.x * 1000},${p.y * 1000}`).join(" ");
      const pl = document.createElementNS("http://www.w3.org/2000/svg", "polygon");
      pl.setAttribute("points", pts);
      pl.setAttribute("fill", "rgba(122,162,255,0.12)");
      pl.setAttribute("stroke", "rgba(122,162,255,0.7)");
      pl.setAttribute("stroke-width", "2");
      overlay.appendChild(pl);
    });
  }

  if (dots && dots.length) {
    dots.forEach((d) => {
      const dot = el("div", { class: `dot ${d.className || ""}`.trim() });
      dot.style.left = `${d.x * 100}%`;
      dot.style.top = `${d.y * 100}%`;
      if (d.title) dot.title = d.title;
      if (d.onClick) dot.addEventListener("click", (e) => { e.stopPropagation(); d.onClick(d); });
      container.appendChild(dot);
    });
  }

  if (labels && labels.length) {
    labels.forEach((lb) => {
      const n = el("div", { class: `map-label ${lb.className || ""}`.trim(), text: lb.text || "" });
      n.style.left = `${lb.x * 100}%`;
      n.style.top = `${lb.y * 100}%`;
      container.appendChild(n);
    });
  }

  // Viktigt: lyssna på klick på själva bilden (inte containern),
  // annars kan rect-beräkningen bli fel/0 tidigt och ge null-koordinater.
  img.addEventListener("click", (evt) => {
    if (!onClick) return;
    const { x, y } = normClick(img, evt);
    if (x == null || y == null) return;
    onClick({ x, y });
  });
}

async function refreshSets() {
  const r = await api("/api/sets");
  state.sets = r.data || [];
  const selA = $("#admin-set-select");
  selA.innerHTML = "";
  state.sets.forEach((s) => {
    selA.appendChild(el("option", { value: s.id, text: `${s.name} (${s.id})` }));
  });
  if (!state.adminSetId && state.sets[0]) state.adminSetId = state.sets[0].id;
  if (state.adminSetId) selA.value = state.adminSetId;
  renderQuizHome();
}

function selectedSetId(kind) {
  if (kind === "admin") return $("#admin-set-select").value || null;
  return null;
}

function setQuizMode(mode) {
  state.quiz.mode = mode;
  $("#mode-rand10")?.classList.toggle("active", mode === "rand10");
  $("#mode-randHalf")?.classList.toggle("active", mode === "randHalf");
  $("#mode-all")?.classList.toggle("active", mode === "all");
}

function showQuizHome() {
  $("#quiz-home") && ($("#quiz-home").style.display = "");
  $("#quiz-play") && ($("#quiz-play").style.display = "none");
}

function showQuizPlay() {
  $("#quiz-home") && ($("#quiz-home").style.display = "none");
  $("#quiz-play") && ($("#quiz-play").style.display = "");
}

function renderQuizHome() {
  const root = $("#quiz-set-list");
  if (!root) return;
  root.innerHTML = "";
  if (!state.sets.length) {
    root.appendChild(el("div", { class: "hint", text: "Inga set ännu. Skapa ett i Admin." }));
    return;
  }
  state.sets.forEach((s) => {
    const left = el("div", {}, [
      el("div", { class: "title", text: s.name }),
      el("div", { class: "meta", text: s.hasImage ? "Har bild" : "Ingen bild än" }),
    ]);
    const btnStart = el("button", { class: "play-btn", text: "Start" });
    btnStart.addEventListener("click", () => startQuiz(s.id));
    const btnMap = el("button", { class: "secondary play-btn", text: "Karta" });
    btnMap.addEventListener("click", () => showMapPreview(s.id));
    const btnPdf = el("button", { class: "secondary play-btn", text: "PDF" });
    btnPdf.addEventListener("click", () => generatePdfForSet(s.id));
    const right = el("div", { class: "row", style: "gap:8px; align-items:center;" }, [btnMap, btnStart]);
    const right2 = el("div", { class: "row", style: "gap:8px; align-items:center;" }, [btnPdf, btnMap, btnStart]);
    root.appendChild(el("div", { class: "set-row" }, [left, right2]));
  });
}

function getOrCreateMapPreviewModal() {
  let m = document.querySelector("#map-preview-modal");
  if (m) return m;

  m = document.createElement("div");
  m.id = "map-preview-modal";
  m.className = "modal";
  m.style.display = "none";
  m.setAttribute("aria-hidden", "true");

  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.addEventListener("click", () => showMapPreviewModal(false));

  const card = document.createElement("div");
  card.className = "modal-card wide";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");

  const title = document.createElement("h3");
  title.id = "map-preview-title";
  title.textContent = "Karta";

  const hint = document.createElement("div");
  hint.className = "hint";
  hint.id = "map-preview-hint";

  const row = document.createElement("div");
  row.className = "row";
  row.style.marginTop = "10px";

  const fsBtn = document.createElement("button");
  fsBtn.className = "secondary";
  fsBtn.id = "map-preview-fullscreen";
  fsBtn.textContent = "Fullskärm";
  fsBtn.addEventListener("click", async () => {
    try {
      const cardEl = document.querySelector("#map-preview-card");
      if (!document.fullscreenElement) {
        await cardEl?.requestFullscreen?.();
      } else {
        await document.exitFullscreen?.();
      }
    } catch (e) {
      showToast("Fullskärm stöds inte här.");
    }
  });

  const close = document.createElement("button");
  close.className = "secondary";
  close.textContent = "Stäng";
  close.addEventListener("click", () => showMapPreviewModal(false));

  row.appendChild(fsBtn);
  row.appendChild(close);

  const map = document.createElement("div");
  map.id = "map-preview-map";
  map.className = "map";
  map.style.marginTop = "10px";
  map.style.minHeight = "70vh";

  card.id = "map-preview-card";
  card.appendChild(title);
  card.appendChild(hint);
  card.appendChild(row);
  card.appendChild(map);

  m.appendChild(backdrop);
  m.appendChild(card);
  document.body.appendChild(m);
  return m;
}

function showMapPreviewModal(show) {
  const m = getOrCreateMapPreviewModal();
  if (!show) {
    // Om modalen stängs när den är i fullskärm: lämna fullskärm så vi inte "fastnar" där.
    try {
      if (document.fullscreenElement) document.exitFullscreen?.();
    } catch {}
  }
  m.style.display = show ? "" : "none";
  m.setAttribute("aria-hidden", show ? "false" : "true");
}

async function showMapPreview(setId) {
  showMapPreviewModal(true);
  const meta = await loadSetMeta(setId);
  const title = document.querySelector("#map-preview-title");
  const hint = document.querySelector("#map-preview-hint");
  const mapEl = document.querySelector("#map-preview-map");
  if (title) title.textContent = meta?.set?.name ? `Karta: ${meta.set.name}` : "Karta";

  if (!meta?.imageUrl) {
    if (hint) hint.textContent = "Ingen bild uppladdad för detta set.";
    if (mapEl) mapEl.innerHTML = "";
    return;
  }
  if (hint) hint.textContent = "Alla pass (med namn).";

  const stands = meta.stands || [];
  const dots = stands.map((s) => ({ x: s.x, y: s.y, className: "quiz" }));
  const labels = stands.map((s, i) => ({
    x: s.x,
    y: s.y,
    text: displayStandName(s.name || ""),
    className: "small",
  }));

  renderMap(mapEl, meta, { dots, labels });
}

function sanitizeFilename(s) {
  return String(s || "set")
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9\-_]+/g, "")
    .slice(0, 60) || "set";
}

function displayStandName(name) {
  // Om namnet börjar med "Pass" / "pass" så tar vi bort prefixet i presentationen
  // Ex: "Pass 12" -> "12", "pass 3 Norra" -> "3 Norra"
  const s = String(name || "").trim();
  return s.replace(/^pass\b\s*/i, "").trim();
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function canvasToJpegBytes(canvas) {
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.92));
  const ab = await blob.arrayBuffer();
  return new Uint8Array(ab);
}

function pdfEscapeText(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

function buildPdfWithJpegAndText({ jpegBytes, imgW, imgH, lines }) {
  // Minimal PDF generator: 2 pages (image + list). Uses DCTDecode for JPEG and Helvetica for text.
  const parts = [];
  const offsets = [0]; // dummy for 1-based obj indexing
  const push = (s) => parts.push(typeof s === "string" ? new TextEncoder().encode(s) : s);
  const join = () => {
    const len = parts.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const markOffset = () => {
    const cur = parts.reduce((a, b) => a + b.length, 0);
    offsets.push(cur);
  };

  const pageW = 595; // A4 portrait points
  const pageH = 842;
  const margin = 36;
  const maxW = pageW - margin * 2;
  const maxH = pageH - margin * 2;
  const scale = Math.min(maxW / imgW, maxH / imgH);
  const drawW = imgW * scale;
  const drawH = imgH * scale;
  const x0 = (pageW - drawW) / 2;
  const y0 = (pageH - drawH) / 2;

  const imgContent = `q\n${drawW.toFixed(2)} 0 0 ${drawH.toFixed(2)} ${x0.toFixed(2)} ${y0.toFixed(2)} cm\n/Im0 Do\nQ\n`;
  const imgContentBytes = new TextEncoder().encode(imgContent);

  const fontSize = 12;
  const lineHeight = 14;
  let textY = pageH - margin - fontSize;
  const textLines = [];
  textLines.push("BT");
  textLines.push(`/F1 ${fontSize} Tf`);
  textLines.push(`${margin} ${textY} Td`);
  for (let i = 0; i < lines.length; i++) {
    const t = pdfEscapeText(lines[i]);
    if (i > 0) textLines.push(`0 -${lineHeight} Td`);
    textLines.push(`(${t}) Tj`);
  }
  textLines.push("ET");
  const textContentBytes = new TextEncoder().encode(textLines.join("\n") + "\n");

  push("%PDF-1.4\n%\xFF\xFF\xFF\xFF\n");

  // 1: catalog
  markOffset(); push("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
  // 2: pages
  markOffset(); push("2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n");
  // 3: page1 (image)
  markOffset();
  push(`3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageW} ${pageH}] /Resources << /XObject << /Im0 6 0 R >> >> /Contents 5 0 R >>\nendobj\n`);
  // 4: page2 (text)
  markOffset();
  push(`4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageW} ${pageH}] /Resources << /Font << /F1 7 0 R >> >> /Contents 8 0 R >>\nendobj\n`);
  // 5: image content stream
  markOffset();
  push(`5 0 obj\n<< /Length ${imgContentBytes.length} >>\nstream\n`);
  push(imgContentBytes);
  push("endstream\nendobj\n");
  // 6: image xobject (jpeg)
  markOffset();
  push(`6 0 obj\n<< /Type /XObject /Subtype /Image /Width ${imgW} /Height ${imgH} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${jpegBytes.length} >>\nstream\n`);
  push(jpegBytes);
  push("\nendstream\nendobj\n");
  // 7: font
  markOffset();
  push("7 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");
  // 8: text content stream
  markOffset();
  push(`8 0 obj\n<< /Length ${textContentBytes.length} >>\nstream\n`);
  push(textContentBytes);
  push("endstream\nendobj\n");

  const xrefStart = parts.reduce((a, b) => a + b.length, 0);
  const objCount = offsets.length - 1;
  push("xref\n");
  push(`0 ${objCount + 1}\n`);
  push("0000000000 65535 f \n");
  for (let i = 1; i <= objCount; i++) {
    const off = offsets[i].toString().padStart(10, "0");
    push(`${off} 00000 n \n`);
  }
  push("trailer\n");
  push(`<< /Size ${objCount + 1} /Root 1 0 R >>\n`);
  push("startxref\n");
  push(`${xrefStart}\n`);
  push("%%EOF\n");
  return join();
}

async function generatePdfForSet(setId) {
  try {
    showToast("Skapar PDF…", 1200);
    const meta = await loadSetMeta(setId);
    if (!meta?.imageUrl) {
      showToast("Ingen bild för detta set.");
      return;
    }
    const stands = meta.stands || [];
    if (!stands.length) {
      showToast("Inga pass i detta set.");
      return;
    }

    // Rendera karta + passnummer till canvas (och exportera som JPEG för enkel PDF-embed).
    const img = new Image();
    img.src = meta.imageUrl;
    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = reject;
    });

    const targetW = Math.min(1600, Math.max(900, img.naturalWidth || 1200));
    const scale = targetW / (img.naturalWidth || targetW);
    const targetH = Math.round((img.naturalHeight || 800) * scale);

    const canvas = document.createElement("canvas");
    canvas.width = targetW;
    canvas.height = targetH;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0, targetW, targetH);

    // Dots + labels
    ctx.font = "bold 18px ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial";
    ctx.textBaseline = "top";

    const truncateText = (text, maxWidth) => {
      const t = String(text || "");
      if (!t) return "";
      if (ctx.measureText(t).width <= maxWidth) return t;
      const ell = "…";
      let lo = 0, hi = t.length;
      while (lo < hi) {
        const mid = Math.floor((lo + hi) / 2);
        const cand = t.slice(0, mid) + ell;
        if (ctx.measureText(cand).width <= maxWidth) lo = mid + 1;
        else hi = mid;
      }
      return t.slice(0, Math.max(0, lo - 1)) + ell;
    };

    for (let i = 0; i < stands.length; i++) {
      const s = stands[i];
      const x = Math.round(s.x * targetW);
      const y = Math.round(s.y * targetH);
      // dot
      ctx.fillStyle = "#ffffff";
      ctx.strokeStyle = "#000000";
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.arc(x, y, 6, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
      // label bubble
      const txt = String(displayStandName(s.name || ""));
      const pad = 4;
      const maxLabelW = Math.min(320, Math.max(140, targetW * 0.25));
      const txt2 = truncateText(txt, maxLabelW);
      const tw = ctx.measureText(txt2).width;
      const bx = x + 10;
      const by = y - 10;
      ctx.fillStyle = "rgba(0,0,0,0.65)";
      ctx.fillRect(bx, by, tw + pad * 2, 22);
      ctx.fillStyle = "#ffffff";
      ctx.fillText(txt2, bx + pad, by + 2);
    }

    const jpegBytes = await canvasToJpegBytes(canvas);
    const lines = stands
      .map((s) => displayStandName(s.name || ""))
      .map((s) => s.trim())
      .filter(Boolean);
    const pdfBytes = buildPdfWithJpegAndText({ jpegBytes, imgW: canvas.width, imgH: canvas.height, lines });
    const blob = new Blob([pdfBytes], { type: "application/pdf" });
    const fname = `jaktpass-${sanitizeFilename(meta?.set?.name)}-pass.pdf`;
    downloadBlob(blob, fname);
    showToast("PDF klar.");
  } catch (e) {
    showToast("Kunde inte skapa PDF.");
    console.error(e);
  }
}

async function loadSetMeta(setId) {
  const r = await api(`/api/sets/${encodeURIComponent(setId)}`);
  return r.data;
}

function renderStandsList(meta) {
  const ul = $("#stands-list");
  ul.innerHTML = "";
  (meta.stands || []).forEach((s) => {
    const li = el("li", {}, [
      el("div", { text: `${s.name}  (${s.id})` }),
      el("div", { text: `x=${s.x.toFixed?.(4) ?? s.x}, y=${s.y.toFixed?.(4) ?? s.y}` }),
    ]);
    li.addEventListener("click", () => {
      state.selectedStandId = s.id;
      $("#selected-stand-id").value = s.id;
      $("#stand-name").value = s.name || "";
      $("#stand-x").value = s.x;
      $("#stand-y").value = s.y;
      $("#stand-note").value = s.note || "";
    });
    ul.appendChild(li);
  });
}

function renderAdmin() {
  $("#admin-set-meta").textContent = state.adminMeta ? fmt(state.adminMeta) : "";

  const dots = (state.adminMeta?.stands || []).map((s) => ({
    id: s.id,
    x: s.x,
    y: s.y,
    className: "admin",
    title: `${s.name}\n${s.id}`,
    onClick: () => {
      state.selectedStandId = s.id;
      $("#selected-stand-id").value = s.id;
      $("#stand-name").value = s.name || "";
      $("#stand-x").value = s.x;
      $("#stand-y").value = s.y;
      $("#stand-note").value = s.note || "";
    },
  }));

  renderMap($("#admin-map"), state.adminMeta, {
    dots,
    onClick: ({ x, y }) => {
      if (x == null || y == null) return;
      // annars: sätt stand x/y draft
      $("#stand-x").value = x;
      $("#stand-y").value = y;
    },
  });

  renderStandsList(state.adminMeta || {});
}

async function refreshAdminMeta() {
  const setId = selectedSetId("admin");
  if (!setId) return;
  state.adminSetId = setId;
  state.adminMeta = await loadSetMeta(setId);
  renderAdmin();
}

function renderQuizPack(meta, pack) {
  const total = (pack.questions || []).length;
  $("#quiz-progress").textContent = `${state.quiz.idx}/${total}`;
  $("#quiz-question").textContent = state.quiz.current ? state.quiz.current.name : "-";
  updateScore();

  const visibleById = {};
  (pack.visibleStands || []).forEach((s) => { visibleById[s.id] = s; });

  const labels = [];
  Object.entries(state.quiz.labelsPersistent || {}).forEach(([id, name]) => {
    const vs = visibleById[id];
    if (!vs) return;
    labels.push({ x: vs.x, y: vs.y, text: name, className: "" });
  });

  const dots = (pack.visibleStands || []).map((s) => ({
    x: s.x,
    y: s.y,
    className: `quiz ${state.quiz.dotStates?.[s.id] || ""}`.trim(),
    onClick: () => {
      if (!state.quiz.current) return;
      // Viktigt: läs alltid aktuell fråga här (inte en fångad variabel från första rendern),
      // annars fastnar man efter att frågan har bytts.
      const wantId = state.quiz.current?.standId;
      if (!wantId) return;
      if (s.id === wantId) {
        // Om vi är i "reveal-läge" (3 fel): behåll röd färg och gå vidare först när man klickat rätt prick.
        if (state.quiz.revealActive && state.quiz.revealId === wantId) {
          state.quiz.dotStates[wantId] = "reveal";
          state.quiz.labelsPersistent[wantId] =
            state.quiz.current?.name || state.quiz.standNameById?.[wantId] || wantId;
          state.quiz.revealActive = false;
          state.quiz.revealId = null;
          state.quiz.attempts = 0;
          advanceQuiz();
          renderQuizPack(state.quiz.meta, state.quiz.pack);
          return;
        }

        const attemptNo = state.quiz.attempts + 1;
        if (attemptNo === 1) state.quiz.dotStates[wantId] = "correct1";
        else if (attemptNo === 2) state.quiz.dotStates[wantId] = "correct2";
        else state.quiz.dotStates[wantId] = "correct3";

        state.quiz.labelsPersistent[wantId] =
          state.quiz.current?.name || state.quiz.standNameById?.[wantId] || wantId;

        state.quiz.attempts = 0;
        advanceQuiz();
        renderQuizPack(state.quiz.meta, state.quiz.pack);
        return;
      }

      // Felklick: visa temporär label med vad man klickade på (fadar ut inom 5s)
      state.quiz.attempts += 1;
      // Seterra-liknande: varje felklick är ett misstag (men vi cappar per fråga till 3 i MVP)
      const qid = wantId;
      const prev = state.quiz.mistakesByQuestion[qid] || 0;
      if (prev < 3) {
        state.quiz.mistakesByQuestion[qid] = prev + 1;
        state.quiz.mistakesTotal += 1;
        updateScore();
      }
      showTempLabel(s.id, s.x, s.y);

      // Efter 3 fel: rätt prick blinkar rött tills man klickar på den.
      if (!state.quiz.revealActive && state.quiz.attempts >= 3) {
        state.quiz.revealActive = true;
        state.quiz.revealId = wantId;
        state.quiz.dotStates[wantId] = "revealBlink";
        state.quiz.labelsPersistent[wantId] =
          state.quiz.current?.name || state.quiz.standNameById?.[wantId] || wantId;
        renderQuizPack(state.quiz.meta, state.quiz.pack);
      }
    },
  }));

  renderMap($("#quiz-map"), meta, { dots, labels });
  // Ingen debug-json i quiz-läget (håller UI:t rent)
  $("#quiz-debug").textContent = "";
}

function showTempLabel(standId, x, y) {
  const name = state.quiz.standNameById?.[standId] || standId;
  const container = $("#quiz-map");
  const n = el("div", { class: "map-label temp", text: name });
  n.style.left = `${x * 100}%`;
  n.style.top = `${y * 100}%`;
  container.appendChild(n);
  // städa bort efter animationen (1s)
  setTimeout(() => {
    try { n.remove(); } catch {}
  }, 1200);
}

function advanceQuiz() {
  const q = state.quiz.pack?.questions || [];
  if (state.quiz.idx >= q.length) {
    state.quiz.current = null;
    $("#quiz-question").textContent = "Klart!";
    const pct = updateScore();
    showFinishModal(true, pct);
    return;
  }
  state.quiz.current = q[state.quiz.idx];
  state.quiz.idx += 1;
  $("#quiz-progress").textContent = `${state.quiz.idx}/${q.length}`;
  $("#quiz-question").textContent = state.quiz.current.name;
  updateScore();
}

function showFinishModal(show, pct) {
  const m = $("#quiz-finish-modal");
  if (!m) return;
  m.style.display = show ? "" : "none";
  m.setAttribute("aria-hidden", show ? "false" : "true");
  if (show) {
    $("#finish-score").textContent = `${pct}%`;
  }
}

async function startQuiz(setId) {
  state.quiz.selectedSetId = setId;
  const mode = state.quiz.mode || "rand10";
  const qs = new URLSearchParams();
  qs.set("mode", mode);

  const meta = await loadSetMeta(setId);
  const r = await api(`/api/sets/${encodeURIComponent(setId)}/quiz?${qs.toString()}`);
  const pack = r.data;
  state.quiz.pack = pack;
  state.quiz.meta = meta;
  state.quiz.idx = 0;
  state.quiz.current = null;
  state.quiz.attempts = 0;
  state.quiz.mistakesTotal = 0;
  state.quiz.mistakesByQuestion = {};
  state.quiz.dotStates = {};
  state.quiz.labelsPersistent = {};
  state.quiz.revealActive = false;
  state.quiz.revealId = null;
  // map standId -> name för labels vid felklick
  const map = {};
  (meta.stands || []).forEach((s) => { map[s.id] = s.name; });
  state.quiz.standNameById = map;
  showFinishModal(false, 0);
  showQuizPlay();
  advanceQuiz();
  renderQuizPack(meta, pack);
}

// ---- wire up ----

$("#tab-admin").addEventListener("click", () => navigateTo("admin"));
$("#tab-quiz").addEventListener("click", () => navigateTo("quiz"));

$("#login-submit").addEventListener("click", async () => {
  const user = $("#login-user")?.value || "";
  const pass = $("#login-pass")?.value || "";
  setCreds(user, pass);
  try {
    await api("/api/admin/ping", { admin: true });
    setAdminAuthed(true);
    showToast("Inloggad.");
  } catch (e) {
    setAdminAuthed(false);
    showToast("Fel användarnamn/lösenord.");
  }
});

$("#login-cancel").addEventListener("click", () => {
  navigateTo("quiz");
});

$("#logout-btn").addEventListener("click", () => {
  setCreds("", "");
  setAdminAuthed(false);
  showToast("Utloggad.");
});

$("#create-set").addEventListener("click", async () => {
  const name = $("#new-set-name").value.trim();
  if (!name) return alert("Ange namn.");
  try {
    await api("/api/admin/sets", { method: "POST", admin: true, jsonBody: { name } });
    $("#new-set-name").value = "";
    await refreshSets();
    await refreshAdminMeta();
  } catch (e) {
    alert(String(e));
  }
});

$("#refresh-admin").addEventListener("click", async () => {
  try {
    await refreshSets();
    await refreshAdminMeta();
  } catch (e) {
    alert(String(e));
  }
});

$("#delete-set").addEventListener("click", async () => {
  const setId = selectedSetId("admin");
  if (!setId) return alert("Välj set.");
  if (!confirm("Radera set? Detta tar bort meta.json och bildfilen på disk.")) return;
  try {
    await api(`/api/admin/sets/${encodeURIComponent(setId)}`, { method: "DELETE", admin: true });
    await refreshSets();
    state.adminMeta = null;
    $("#admin-set-meta").textContent = "";
    await refreshAdminMeta();
    showToast("Set raderat.");
  } catch (e) {
    alert(String(e));
  }
});

$("#admin-set-select").addEventListener("change", async () => {
  try { await refreshAdminMeta(); } catch (e) { alert(String(e)); }
});

$("#upload-image").addEventListener("click", async () => {
  const setId = selectedSetId("admin");
  const f = $("#image-file").files[0];
  if (!setId) return alert("Välj set.");
  if (!f) return alert("Välj fil.");
  const fd = new FormData();
  fd.append("file", f);
  try {
    await api(`/api/admin/sets/${encodeURIComponent(setId)}/image`, { method: "POST", admin: true, multipart: fd });
    await refreshAdminMeta();
  } catch (e) {
    alert(String(e));
  }
});

$("#create-stand").addEventListener("click", async () => {
  const setId = selectedSetId("admin");
  const name = $("#stand-name").value.trim();
  const x = clamp01($("#stand-x").value);
  const y = clamp01($("#stand-y").value);
  const note = $("#stand-note").value.trim();
  if (!setId) return alert("Välj set.");
  if (!name) return alert("Ange namn.");
  if (x == null || y == null) return alert("Ogiltiga x/y.");
  try {
    await api(`/api/admin/sets/${encodeURIComponent(setId)}/stands`, {
      method: "POST",
      admin: true,
      jsonBody: note ? { name, x, y, note } : { name, x, y },
    });
    await refreshAdminMeta();
  } catch (e) {
    alert(String(e));
  }
});

$("#patch-stand").addEventListener("click", async () => {
  const standId = $("#selected-stand-id").value.trim();
  if (!standId) return alert("Välj stand.");
  const name = $("#stand-name").value.trim();
  const x = clamp01($("#stand-x").value);
  const y = clamp01($("#stand-y").value);
  const note = $("#stand-note").value.trim();
  const body = {};
  if (name) body.name = name;
  if (x != null) body.x = x;
  if (y != null) body.y = y;
  body.note = note; // tillåt tom sträng
  try {
    await api(`/api/admin/stands/${encodeURIComponent(standId)}`, { method: "PATCH", admin: true, jsonBody: body });
    await refreshAdminMeta();
  } catch (e) {
    alert(String(e));
  }
});

$("#delete-stand").addEventListener("click", async () => {
  const standId = $("#selected-stand-id").value.trim();
  if (!standId) return alert("Välj stand.");
  if (!confirm("Radera stand?")) return;
  try {
    await api(`/api/admin/stands/${encodeURIComponent(standId)}`, { method: "DELETE", admin: true });
    $("#selected-stand-id").value = "";
    await refreshAdminMeta();
  } catch (e) {
    alert(String(e));
  }
});

$("#mode-rand10")?.addEventListener("click", () => setQuizMode("rand10"));
$("#mode-randHalf")?.addEventListener("click", () => setQuizMode("randHalf"));
$("#mode-all")?.addEventListener("click", () => setQuizMode("all"));

$("#quiz-back")?.addEventListener("click", () => {
  showFinishModal(false, 0);
  showQuizHome();
});

$("#finish-to-list")?.addEventListener("click", () => {
  showFinishModal(false, 0);
  showQuizHome();
});

$("#finish-restart")?.addEventListener("click", () => {
  const sid = state.quiz.selectedSetId;
  if (!sid) return;
  showFinishModal(false, 0);
  startQuiz(sid).catch((e) => alert(String(e)));
});

// init
(() => {
  const { user, pass } = getCreds();
  if ($("#login-user")) $("#login-user").value = user;
  if ($("#login-pass")) $("#login-pass").value = pass;
  setQuizMode(state.quiz.mode);
  showQuizHome();
  showFinishModal(false, 0);
  // Välj vy baserat på URL ("/admin" eller "/quiz")
  navigateTo(viewFromPath(location.pathname));
  window.addEventListener("popstate", () => {
    showView(viewFromPath(location.pathname));
    if (viewFromPath(location.pathname) === "admin") checkAdminAuthAndGate();
  });
  // Init: om admin är aktiv, auth-gate:a
  if (viewFromPath(location.pathname) === "admin") checkAdminAuthAndGate();
  refreshSets()
    .then(() => refreshAdminMeta())
    .catch((e) => console.error(e));
})();


