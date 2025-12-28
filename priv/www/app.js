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
  // Enkel "måste logga in" hint: om inga creds, scrolla till auth-kortet.
  if (view === "admin") {
    const { user, pass } = getCreds();
    if (!user || !pass) {
      setTimeout(() => {
        try { $("#admin-user")?.focus(); } catch {}
      }, 0);
    }
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
  const selQ = $("#quiz-set-select");
  selA.innerHTML = "";
  selQ.innerHTML = "";
  state.sets.forEach((s) => {
    selA.appendChild(el("option", { value: s.id, text: `${s.name} (${s.id})` }));
    selQ.appendChild(el("option", { value: s.id, text: `${s.name}` }));
  });
  if (!state.adminSetId && state.sets[0]) state.adminSetId = state.sets[0].id;
  if (state.adminSetId) selA.value = state.adminSetId;
  if (state.sets[0]) selQ.value = state.sets[0].id;
}

function selectedSetId(kind) {
  if (kind === "admin") return $("#admin-set-select").value || null;
  if (kind === "quiz") return $("#quiz-set-select").value || null;
  return null;
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
  $("#quiz-debug").textContent = fmt(pack);
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
    showToast(`Klart! Du fick ${pct}% score.`);
    return;
  }
  state.quiz.current = q[state.quiz.idx];
  state.quiz.idx += 1;
  $("#quiz-progress").textContent = `${state.quiz.idx}/${q.length}`;
  $("#quiz-question").textContent = state.quiz.current.name;
  updateScore();
}

async function startQuiz() {
  const setId = selectedSetId("quiz");
  const mode = ($("#quiz-mode")?.value || "rand10");
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
  advanceQuiz();
  renderQuizPack(meta, pack);
}

// ---- wire up ----

$("#tab-admin").addEventListener("click", () => navigateTo("admin"));
$("#tab-quiz").addEventListener("click", () => navigateTo("quiz"));

$("#save-creds").addEventListener("click", () => {
  setCreds($("#admin-user").value, $("#admin-pass").value);
  alert("Sparat.");
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

$("#start-quiz").addEventListener("click", async () => {
  try { await startQuiz(); } catch (e) { alert(String(e)); }
});

// init
(() => {
  const { user, pass } = getCreds();
  $("#admin-user").value = user;
  $("#admin-pass").value = pass;
  // Välj vy baserat på URL ("/admin" eller "/quiz")
  navigateTo(viewFromPath(location.pathname));
  window.addEventListener("popstate", () => {
    showView(viewFromPath(location.pathname));
  });
  refreshSets()
    .then(() => refreshAdminMeta())
    .catch((e) => console.error(e));
})();


