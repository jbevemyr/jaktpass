/* Jaktpass v2 (multi-admin) - separat UI. Hash-routing: #/login, #/register, #/admin, #/quiz/<shareId> */

const $ = (sel) => document.querySelector(sel);

function toast(msg, ms = 1400) {
  const t = $("#v2-toast");
  if (!t) return;
  t.textContent = msg;
  t.style.display = "";
  requestAnimationFrame(() => t.classList.add("show"));
  setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => (t.style.display = "none"), 200);
  }, ms);
}

function getOrCreateFinishModal() {
  let m = document.querySelector("#v2-finish-modal");
  if (m) return m;

  m = document.createElement("div");
  m.id = "v2-finish-modal";
  m.className = "modal";
  m.style.display = "none";
  m.setAttribute("aria-hidden", "true");

  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.addEventListener("click", () => showFinishModal(false));

  const card = document.createElement("div");
  card.className = "modal-card";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");

  const title = document.createElement("h3");
  title.id = "v2-finish-title";
  title.textContent = "Resultat";

  const score = document.createElement("div");
  score.id = "v2-finish-score";
  score.className = "pill";
  score.style.display = "inline-block";
  score.style.marginBottom = "10px";

  const name = document.createElement("input");
  name.id = "v2-finish-name";
  name.placeholder = "Ditt namn";

  const btnSave = document.createElement("button");
  btnSave.id = "v2-finish-save";
  btnSave.textContent = "Spara till topplista";

  const lbTitle = document.createElement("div");
  lbTitle.className = "small";
  lbTitle.style.marginTop = "10px";
  lbTitle.textContent = "Topplista";

  const list = document.createElement("ol");
  list.id = "v2-finish-leaderboard";
  list.style.marginTop = "6px";

  const btnClose = document.createElement("button");
  btnClose.className = "secondary";
  btnClose.textContent = "Stäng";
  btnClose.addEventListener("click", () => showFinishModal(false));

  const row1 = document.createElement("div");
  row1.className = "row";
  row1.style.gap = "8px";
  row1.appendChild(name);
  row1.appendChild(btnSave);

  const row2 = document.createElement("div");
  row2.className = "row";
  row2.style.justifyContent = "flex-end";
  row2.appendChild(btnClose);

  card.appendChild(title);
  card.appendChild(score);
  card.appendChild(row1);
  card.appendChild(lbTitle);
  card.appendChild(list);
  card.appendChild(row2);

  m.appendChild(backdrop);
  m.appendChild(card);
  document.body.appendChild(m);
  return m;
}

function renderLeaderboard(listEl, items) {
  listEl.innerHTML = "";
  if (!items || !items.length) {
    const li = document.createElement("li");
    li.textContent = "Ingen topplista ännu.";
    listEl.appendChild(li);
    return;
  }
  items.slice(0, 20).forEach((it) => {
    const li = document.createElement("li");
    li.style.display = "flex";
    li.style.justifyContent = "space-between";
    li.style.gap = "10px";
    const left = document.createElement("span");
    left.textContent = it.name || "";
    const right = document.createElement("span");
    right.className = "pill";
    right.textContent = `${it.score}%`;
    li.appendChild(left);
    li.appendChild(right);
    listEl.appendChild(li);
  });
}

async function showFinishModal(opts, scoreValue, shareId, mode) {
  const m = getOrCreateFinishModal();
  const title = document.querySelector("#v2-finish-title");
  const score = document.querySelector("#v2-finish-score");
  const name = document.querySelector("#v2-finish-name");
  const btnSave = document.querySelector("#v2-finish-save");
  const list = document.querySelector("#v2-finish-leaderboard");

  if (!opts) {
    m.style.display = "none";
    m.setAttribute("aria-hidden", "true");
    return;
  }
  title.textContent = "Resultat";
  score.textContent = `Score: ${scoreValue}%`;
  name.value = name.value || "";

  // Ladda topplista
  try {
    const r = await api(`/api/v2/quiz/${encodeURIComponent(shareId)}/leaderboard?mode=${encodeURIComponent(mode || "all")}`);
    renderLeaderboard(list, r?.data?.items || []);
  } catch {
    renderLeaderboard(list, []);
  }

  btnSave.onclick = async () => {
    const nm = (name.value || "").trim();
    if (!nm) return toast("Skriv ditt namn.");
    try {
      const r = await api(`/api/v2/quiz/${encodeURIComponent(shareId)}/leaderboard`, { method: "POST", jsonBody: { name: nm, score: scoreValue, mode: mode || "all" } });
      renderLeaderboard(list, r?.data?.items || []);
      toast("Sparat.");
    } catch {
      toast("Kunde inte spara.");
    }
  };

  m.style.display = "";
  m.setAttribute("aria-hidden", "false");
}

async function api(path, { method = "GET", jsonBody } = {}) {
  const res = await fetch(path, {
    method,
    headers: jsonBody ? { "Content-Type": "application/json" } : undefined,
    body: jsonBody ? JSON.stringify(jsonBody) : undefined,
    credentials: "include",
  });
  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("application/json") ? await res.json().catch(() => null) : await res.text();
  if (!res.ok) {
    const err = body && body.error ? body.error : `HTTP ${res.status}`;
    throw new Error(err);
  }
  return body;
}

async function apiForm(path, formData, { method = "POST" } = {}) {
  const res = await fetch(path, {
    method,
    body: formData,
    credentials: "include",
  });
  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("application/json") ? await res.json().catch(() => null) : await res.text();
  if (!res.ok) {
    const err = body && body.error ? body.error : `HTTP ${res.status}`;
    throw new Error(err);
  }
  return body;
}

function route() {
  const h = (location.hash || "#/admin").replace(/^#/, "");
  const parts = h.split("/").filter(Boolean);
  return parts;
}

function navTo(hash) {
  location.hash = hash;
}

function render(el) {
  const root = $("#v2-view");
  root.innerHTML = "";
  root.appendChild(el);
}

function row(children) {
  const d = document.createElement("div");
  d.className = "row";
  children.forEach((c) => d.appendChild(c));
  return d;
}

function label(text, input) {
  const l = document.createElement("label");
  l.textContent = text;
  l.appendChild(input);
  return l;
}

function h2(text) {
  const e = document.createElement("h2");
  e.textContent = text;
  return e;
}

function pSmall(text) {
  const e = document.createElement("div");
  e.className = "small";
  e.textContent = text;
  return e;
}

async function ensureMe() {
  try {
    const r = await api("/api/v2/me");
    return r?.data?.admin || null;
  } catch {
    return null;
  }
}

function setAuthedUI(authed) {
  $("#v2-nav-logout").style.display = authed ? "" : "none";
  $("#v2-nav-login").style.display = authed ? "none" : "";
  $("#v2-nav-register").style.display = authed ? "none" : "";
}

const v2state = {
  selectedSetId: null,
  moveStandId: null,
  newSymbol: "dot",
};

function getOrCreateStandCreateModal() {
  let m = document.querySelector("#v2-stand-create-modal");
  if (m) return m;

  m = document.createElement("div");
  m.id = "v2-stand-create-modal";
  m.className = "modal";
  m.style.display = "none";
  m.setAttribute("aria-hidden", "true");

  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";

  const card = document.createElement("div");
  card.className = "modal-card";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");

  const title = document.createElement("h3");
  title.textContent = "Skapa pass";

  const name = document.createElement("input");
  name.id = "v2-stand-create-name";
  name.placeholder = "Passnamn";

  const symWrap = document.createElement("div");
  symWrap.id = "v2-stand-create-symbol";
  symWrap.className = "sym-choice";

  const btnOk = document.createElement("button");
  btnOk.id = "v2-stand-create-ok";
  btnOk.textContent = "Skapa";
  const btnCancel = document.createElement("button");
  btnCancel.className = "secondary";
  btnCancel.id = "v2-stand-create-cancel";
  btnCancel.textContent = "Avbryt";

  const r1 = document.createElement("div");
  r1.className = "row";
  r1.style.gap = "8px";
  r1.appendChild(label("Namn", name));

  const rSym = document.createElement("div");
  rSym.appendChild(Object.assign(document.createElement("div"), { className: "small", textContent: "Symbol" }));
  rSym.appendChild(symWrap);

  const r2 = document.createElement("div");
  r2.className = "row";
  r2.style.justifyContent = "flex-end";
  r2.style.gap = "8px";
  r2.appendChild(btnCancel);
  r2.appendChild(btnOk);

  card.appendChild(title);
  card.appendChild(r1);
  card.appendChild(rSym);
  card.appendChild(r2);

  m.appendChild(backdrop);
  m.appendChild(card);
  document.body.appendChild(m);
  return m;
}

function showStandCreateModal({ defaultName = "", defaultSymbol = "dot" } = {}) {
  const m = getOrCreateStandCreateModal();
  const name = document.querySelector("#v2-stand-create-name");
  const symWrap = document.querySelector("#v2-stand-create-symbol");
  const btnOk = document.querySelector("#v2-stand-create-ok");
  const btnCancel = document.querySelector("#v2-stand-create-cancel");
  const backdrop = m.querySelector(".modal-backdrop");

  name.value = defaultName || "";
  let selected = defaultSymbol || "dot";

  // render symbol buttons
  symWrap.innerHTML = "";
  const symbols = [
    ["dot", "Cirkel"],
    ["square", "Fyrkant"],
    ["triangle", "Triangel"],
    ["star", "Stjärna"],
  ];
  const btns = [];
  symbols.forEach(([v, labelTxt]) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = v === selected ? "active" : "";
    const preview = document.createElement("div");
    preview.className = `dot sym-${v}`;
    // färga preview som admin (gult) så den syns tydligt
    preview.classList.add("admin");
    const txt = document.createElement("span");
    txt.textContent = labelTxt;
    b.appendChild(preview);
    b.appendChild(txt);
    b.addEventListener("click", () => {
      selected = v;
      btns.forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
    });
    btns.push(b);
    symWrap.appendChild(b);
  });

  m.style.display = "";
  m.setAttribute("aria-hidden", "false");
  setTimeout(() => name.focus(), 0);

  return new Promise((resolve) => {
    const close = (val) => {
      m.style.display = "none";
      m.setAttribute("aria-hidden", "true");
      btnOk.onclick = null;
      btnCancel.onclick = null;
      backdrop.onclick = null;
      resolve(val);
    };
    backdrop.onclick = () => close(null);
    btnCancel.onclick = () => close(null);
    btnOk.onclick = () => {
      const nm = (name.value || "").trim();
      if (!nm) return toast("Ange namn.");
      close({ name: nm, symbol: selected });
    };
  });
}

function normClick(img, evt) {
  const rect = img.getBoundingClientRect();
  const w = rect.width || 0;
  const h = rect.height || 0;
  if (!w || !h) return { x: null, y: null };
  const x = (evt.clientX - rect.left) / w;
  const y = (evt.clientY - rect.top) / h;
  if (!isFinite(x) || !isFinite(y)) return { x: null, y: null };
  return { x: Math.max(0, Math.min(1, x)), y: Math.max(0, Math.min(1, y)) };
}

async function fetchSet(setId) {
  const r = await api(`/api/v2/sets/${encodeURIComponent(setId)}`);
  return r?.data || null;
}

function standRow(setId, stand) {
  const d = document.createElement("div");
  d.className = "row";
  d.style.justifyContent = "space-between";
  d.style.alignItems = "center";
  d.style.gap = "8px";

  const left = document.createElement("div");
  left.appendChild(Object.assign(document.createElement("div"), { className: "title", textContent: stand.name || "" }));
  left.appendChild(Object.assign(document.createElement("div"), { className: "small", textContent: `x=${(stand.x ?? 0).toFixed(3)} y=${(stand.y ?? 0).toFixed(3)}` }));

  const right = document.createElement("div");
  right.className = "row";
  right.style.gap = "8px";

  const btnMove = document.createElement("button");
  btnMove.className = "secondary";
  btnMove.textContent = v2state.moveStandId === stand.id ? "Flyttar…" : "Flytta";
  btnMove.addEventListener("click", async () => {
    v2state.moveStandId = stand.id;
    toast("Klicka på kartan för ny position.");
    await renderAdmin();
  });

  const btnRename = document.createElement("button");
  btnRename.className = "secondary";
  btnRename.textContent = "Byt namn";
  btnRename.addEventListener("click", async () => {
    const nm = prompt("Nytt namn", stand.name || "");
    if (!nm || !nm.trim()) return;
    try {
      await api(`/api/v2/sets/${encodeURIComponent(setId)}/stands/${encodeURIComponent(stand.id)}`, { method: "PATCH", jsonBody: { name: nm.trim() } });
      toast("Uppdaterat.");
      await renderAdmin();
    } catch {
      toast("Kunde inte byta namn.");
    }
  });

  const btnDel = document.createElement("button");
  btnDel.className = "danger";
  btnDel.textContent = "Radera";
  btnDel.addEventListener("click", async () => {
    if (!confirm("Radera pass?")) return;
    try {
      await api(`/api/v2/sets/${encodeURIComponent(setId)}/stands/${encodeURIComponent(stand.id)}`, { method: "DELETE" });
      toast("Raderat.");
      await renderAdmin();
    } catch {
      toast("Kunde inte radera.");
    }
  });

  right.appendChild(btnMove);
  right.appendChild(btnRename);
  right.appendChild(btnDel);

  d.appendChild(left);
  d.appendChild(right);
  return d;
}

function renderMapEditor(meta, setId) {
  const map = document.createElement("div");
  map.className = "map";
  map.style.marginTop = "12px";
  map.style.minHeight = "0";

  const imageUrl = meta?.imageUrl;
  if (!imageUrl) {
    map.appendChild(pSmall("Ladda upp en bild för att kunna placera pass på kartan."));
    return map;
  }

  map.classList.add("has-image");
  const img = document.createElement("img");
  img.src = imageUrl;
  img.alt = "Karta";
  img.draggable = false;
  map.appendChild(img);

  function renderDots() {
    [...map.querySelectorAll(".dot")].forEach((n) => n.remove());
    (meta.stands || []).forEach((s) => {
      const dot = document.createElement("div");
      dot.className = `dot admin sym-${s.symbol || "dot"}`;
      dot.style.left = `${(s.x || 0) * 100}%`;
      dot.style.top = `${(s.y || 0) * 100}%`;
      map.appendChild(dot);
    });
  }

  img.addEventListener("load", renderDots);

  img.addEventListener("click", async (evt) => {
    const { x, y } = normClick(img, evt);
    if (x == null || y == null) return;

    if (v2state.moveStandId) {
      const standId = v2state.moveStandId;
      try {
        await api(`/api/v2/sets/${encodeURIComponent(setId)}/stands/${encodeURIComponent(standId)}`, { method: "PATCH", jsonBody: { x, y } });
        v2state.moveStandId = null;
        toast("Flyttat.");
        await renderAdmin();
      } catch {
        toast("Kunde inte flytta.");
      }
      return;
    }

    const r = await showStandCreateModal({ defaultName: "", defaultSymbol: v2state.newSymbol || "dot" });
    if (!r) return;
    try {
      v2state.newSymbol = r.symbol || "dot";
      await api(`/api/v2/sets/${encodeURIComponent(setId)}/stands`, { method: "POST", jsonBody: { name: r.name, x, y, symbol: r.symbol || "dot" } });
      toast("Skapat.");
      await renderAdmin();
    } catch {
      toast("Kunde inte skapa pass.");
    }
  });

  return map;
}

async function renderLogin() {
  const email = document.createElement("input");
  email.type = "email";
  email.placeholder = "E-post";
  const pass = document.createElement("input");
  pass.type = "password";
  pass.placeholder = "Lösenord";
  const btn = document.createElement("button");
  btn.textContent = "Logga in";
  btn.addEventListener("click", async () => {
    try {
      await api("/api/v2/login", { method: "POST", jsonBody: { email: email.value, password: pass.value } });
      toast("Inloggad.");
      navTo("#/admin");
    } catch (e) {
      toast("Fel inloggning.");
    }
  });

  const wrap = document.createElement("div");
  wrap.appendChild(h2("Logga in"));
  wrap.appendChild(pSmall("V2 använder konto + session-cookie (ingen Basic Auth)."));
  wrap.appendChild(row([label("E-post", email), label("Lösenord", pass), btn]));
  render(wrap);
}

async function renderRegister() {
  const email = document.createElement("input");
  email.type = "email";
  email.placeholder = "E-post";
  const pass = document.createElement("input");
  pass.type = "password";
  pass.placeholder = "Lösenord (minst 8 tecken)";
  const btn = document.createElement("button");
  btn.textContent = "Skapa konto";
  btn.addEventListener("click", async () => {
    try {
      await api("/api/v2/register", { method: "POST", jsonBody: { email: email.value, password: pass.value } });
      toast("Konto skapat.");
      navTo("#/admin");
    } catch (e) {
      toast("Kunde inte skapa konto.");
    }
  });

  const wrap = document.createElement("div");
  wrap.appendChild(h2("Registrera administratör"));
  wrap.appendChild(pSmall("Skapa ett konto för att kunna skapa egna set och dela quiz-länkar."));
  wrap.appendChild(row([label("E-post", email), label("Lösenord", pass), btn]));
  render(wrap);
}

function setRow(setObj) {
  const d = document.createElement("div");
  d.className = "set-row";

  const left = document.createElement("div");
  left.appendChild(Object.assign(document.createElement("div"), { className: "title", textContent: setObj.name }));
  // Visa inte "Har bild" (bara visa hint om bild saknas)
  if (!setObj.hasImage) left.appendChild(Object.assign(document.createElement("div"), { className: "meta", textContent: "Ingen bild" }));

  const btnShare = document.createElement("button");
  btnShare.className = "secondary play-btn";
  btnShare.textContent = "Hämta länk";
  btnShare.addEventListener("click", async () => {
    try {
      const r = await api(`/api/v2/sets/${encodeURIComponent(setObj.id)}/share`, { method: "POST" });
      const url0 = r?.data?.shareUrl || "";
      const url = url0 && String(url0).startsWith("http") ? String(url0) : (location.origin + String(url0 || ""));
      const i = $("#v2-share-url");
      if (i) i.value = url;
      toast("Länk klar.");
    } catch {
      toast("Kunde inte skapa länk.");
    }
  });

  const btnQuiz = document.createElement("button");
  btnQuiz.className = "secondary play-btn";
  btnQuiz.textContent = "Öppna quiz";
  btnQuiz.addEventListener("click", () => {
    if (!setObj.shareId) return toast("Skapa länk först.");
    navTo(`#/quiz/${setObj.shareId}`);
  });

  const right = document.createElement("div");
  right.className = "row";
  right.style.gap = "8px";
  right.appendChild(btnShare);
  right.appendChild(btnQuiz);

  d.appendChild(left);
  d.appendChild(right);
  return d;
}

async function renderAdmin() {
  const me = await ensureMe();
  setAuthedUI(!!me);
  if (!me) return navTo("#/login");

  const wrap = document.createElement("div");
  wrap.appendChild(h2("Mina set"));
  wrap.appendChild(pSmall(`Inloggad som ${me.email}.`));

  const name = document.createElement("input");
  name.placeholder = "Set-namn";
  const btnCreate = document.createElement("button");
  btnCreate.textContent = "Skapa set";
  btnCreate.addEventListener("click", async () => {
    if (!name.value.trim()) return toast("Ange namn.");
    try {
      await api("/api/v2/sets", { method: "POST", jsonBody: { name: name.value } });
      name.value = "";
      toast("Skapat.");
      // Vi är redan på #/admin och hashchange triggar inte alltid vid samma hash → re-render direkt.
      await renderAdmin();
    } catch {
      toast("Kunde inte skapa set.");
    }
  });

  const shareUrl = document.createElement("input");
  shareUrl.id = "v2-share-url";
  shareUrl.className = "mono sharebox";
  shareUrl.placeholder = "Quiz-länk kommer här…";
  const btnCopy = document.createElement("button");
  btnCopy.className = "secondary";
  btnCopy.textContent = "Kopiera";
  btnCopy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(shareUrl.value || "");
      toast("Kopierat.");
    } catch {
      toast("Kunde inte kopiera.");
    }
  });

  wrap.appendChild(row([label("Nytt set", name), btnCreate]));
  const cr = document.createElement("div");
  cr.className = "copyrow";
  cr.appendChild(shareUrl);
  cr.appendChild(btnCopy);
  wrap.appendChild(cr);

  let sets = [];
  try {
    const r = await api("/api/v2/sets");
    sets = r?.data || [];
  } catch {
    sets = [];
  }
  if (!sets.length) wrap.appendChild(pSmall("Inga set ännu."));
  else sets.forEach((s) => wrap.appendChild(setRow(s)));

  // ---- Redigera set: bild + pass ----
  if (sets.length) {
    if (!v2state.selectedSetId) v2state.selectedSetId = sets[0].id;

    const sec = document.createElement("div");
    sec.style.marginTop = "14px";
    sec.appendChild(h2("Bild & pass"));

    const sel = document.createElement("select");
    sets.forEach((s) => {
      const o = document.createElement("option");
      o.value = s.id;
      o.textContent = s.name;
      sel.appendChild(o);
    });
    sel.value = v2state.selectedSetId;
    sel.addEventListener("change", async () => {
      v2state.selectedSetId = sel.value;
      v2state.moveStandId = null;
      await renderAdmin();
    });
    sec.appendChild(row([label("Välj set", sel)]));

    let meta = null;
    try {
      meta = await fetchSet(v2state.selectedSetId);
    } catch {
      meta = null;
    }

    const up = document.createElement("div");
    up.className = "row";
    up.style.gap = "8px";
    up.style.alignItems = "center";
    const file = document.createElement("input");
    file.type = "file";
    file.accept = "image/png,image/jpeg,image/webp";
    const btnUp = document.createElement("button");
    btnUp.textContent = "Ladda upp bild";
    btnUp.addEventListener("click", async () => {
      const f = file.files && file.files[0];
      if (!f) return toast("Välj en bildfil.");
      const fd = new FormData();
      fd.append("file", f, f.name);
      try {
        await apiForm(`/api/v2/sets/${encodeURIComponent(v2state.selectedSetId)}/image`, fd);
        toast("Uppladdat.");
        await renderAdmin();
      } catch {
        toast("Kunde inte ladda upp.");
      }
    });
    const btnCancelMove = document.createElement("button");
    btnCancelMove.className = "secondary";
    btnCancelMove.textContent = "Avbryt flytt";
    btnCancelMove.style.display = v2state.moveStandId ? "" : "none";
    btnCancelMove.addEventListener("click", async () => {
      v2state.moveStandId = null;
      toast("Avbrutet.");
      await renderAdmin();
    });
    up.appendChild(file);
    up.appendChild(btnUp);
    up.appendChild(btnCancelMove);
    sec.appendChild(up);

    if (meta) {
      sec.appendChild(renderMapEditor(meta, v2state.selectedSetId));

      const stands = meta.stands || [];
      sec.appendChild(h2(`Pass (${stands.length})`));
      if (!stands.length) sec.appendChild(pSmall("Inga pass ännu. Klicka på kartan för att skapa."));
      else stands.forEach((s) => sec.appendChild(standRow(v2state.selectedSetId, s)));
    } else {
      sec.appendChild(pSmall("Kunde inte läsa set-data."));
    }

    wrap.appendChild(sec);
  }

  render(wrap);
}

async function renderQuiz(shareId) {
  const wrap = document.createElement("div");
  wrap.appendChild(h2("Quiz"));
  wrap.appendChild(pSmall("Denna länk är hemlig: den som har länken kan spela."));

  const mode = document.createElement("select");
  ["rand10", "randHalf", "all"].forEach((m) => {
    const o = document.createElement("option");
    o.value = m;
    o.textContent = m === "rand10" ? "10 pass" : (m === "randHalf" ? "Hälften" : "Alla");
    mode.appendChild(o);
  });

  const btnStart = document.createElement("button");
  btnStart.textContent = "Starta";

  const map = document.createElement("div");
  map.className = "map";
  map.style.marginTop = "12px";
  map.style.minHeight = "0";

  const q = document.createElement("div");
  q.className = "pill";
  q.style.marginTop = "10px";
  q.textContent = "Tryck Start.";

  btnStart.addEventListener("click", async () => {
    try {
      const qs = new URLSearchParams();
      qs.set("mode", mode.value);
      const r = await api(`/api/v2/quiz/${encodeURIComponent(shareId)}?${qs.toString()}`);
      const pack = r?.data;
      const setName = pack?.set?.name || "Quiz";
      wrap.querySelector("h2").textContent = `${setName} – Quiz`;
      const questions = pack?.questions || [];
      const visible = pack?.visibleStands || [];
      const nameById = {};
      questions.forEach((it) => { nameById[it.standId] = it.name; });

      let idx = 0;
      const solved = new Set();
      let mistakes = 0;
      let wrongThis = 0;

      function setQuestionText() {
        if (!questions.length) {
          q.textContent = "Inga pass i detta set.";
          return;
        }
        if (idx >= questions.length) {
          const N = questions.length;
          const M = mistakes;
          const score = Math.round(100 * N / (N + M));
          q.textContent = "Klart!";
          showFinishModal(true, score, shareId, mode.value);
          return;
        }
        const cur = questions[idx];
        q.textContent = `Hitta: ${cur.name} (${idx + 1}/${questions.length})  •  Fel: ${mistakes}`;
      }

      // Rendera karta + prickar (minimal quiz-loop)
      map.innerHTML = "";
      map.classList.add("has-image");
      const img = document.createElement("img");
      img.src = pack.imageUrl;
      map.appendChild(img);
      visible.forEach((s) => {
        const d = document.createElement("div");
        d.className = `dot quiz sym-${s.symbol || "dot"}`;
        d.dataset.id = s.id;
        d.style.left = `${s.x * 100}%`;
        d.style.top = `${s.y * 100}%`;
        d.addEventListener("click", () => {
          if (!questions.length) return;
          if (idx >= questions.length) return;
          const want = questions[idx].standId;
          const got = s.id;
          if (got === want) {
            solved.add(got);
            d.classList.add(wrongThis === 0 ? "correct1" : (wrongThis === 1 ? "correct2" : "correct3"));
            wrongThis = 0;
            idx += 1;
            setQuestionText();
          } else {
            if (wrongThis < 3) {
              wrongThis += 1;
              mistakes += 1;
            }
            toast(`Fel: ${(nameById[got] || "pass")}`);
            if (wrongThis >= 3) {
              // Efter 3 fel: markera rätt prick röd och gå vidare
              const wantEl = map.querySelector(`.dot[data-id="${want}"]`);
              if (wantEl) wantEl.classList.add("reveal");
              wrongThis = 0;
              idx += 1;
              setQuestionText();
            } else {
              setQuestionText();
            }
          }
        });
        map.appendChild(d);
      });
      // Markera redan lösta om vi re-renderar av nån anledning
      [...map.querySelectorAll(".dot")].forEach((el) => {
        const id = el.dataset.id;
        if (solved.has(id)) el.classList.add("correct1");
      });
      setQuestionText();
    } catch {
      toast("Kunde inte starta quiz.");
    }
  });

  wrap.appendChild(row([label("Antal", mode), btnStart]));
  wrap.appendChild(q);
  wrap.appendChild(map);
  render(wrap);
}

async function onRoute() {
  const parts = route();
  const [a, b, c] = parts;
  const me = await ensureMe();
  setAuthedUI(!!me);

  if (a === "register") return renderRegister();
  if (a === "login") return renderLogin();
  if (a === "quiz" && b) return renderQuiz(b);
  return renderAdmin();
}

$("#v2-nav-login").addEventListener("click", () => navTo("#/login"));
$("#v2-nav-register").addEventListener("click", () => navTo("#/register"));
$("#v2-nav-admin").addEventListener("click", () => navTo("#/admin"));
$("#v2-nav-logout").addEventListener("click", async () => {
  try { await api("/api/v2/logout", { method: "POST" }); } catch {}
  toast("Utloggad.");
  navTo("#/login");
});

window.addEventListener("hashchange", onRoute);
onRoute();


