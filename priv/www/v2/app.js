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
      const url = r?.data?.shareUrl || "";
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
      q.textContent = `Frågor: ${(pack.questions || []).length}`;
      // Rendera karta + prickar (enkel visning, v1-quiz logik återkommer när vi bygger vidare)
      map.innerHTML = "";
      const img = document.createElement("img");
      img.src = pack.imageUrl;
      map.appendChild(img);
      (pack.visibleStands || []).forEach((s) => {
        const d = document.createElement("div");
        d.className = "dot";
        d.style.left = `${s.x * 100}%`;
        d.style.top = `${s.y * 100}%`;
        map.appendChild(d);
      });
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


