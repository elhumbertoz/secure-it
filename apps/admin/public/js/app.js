(function () {
  let sessionToken = localStorage.getItem("secureit_session") || "";
  let username = "";
  let serversCache = [];
  let credentialsCache = [];
  let auditCache = [];
  let tokensCache = [];
  let generalTokenId = null;
  let revealTimer = null;
  let revealingCred = null;

  const $ = (id) => document.getElementById(id);

  const loginScreen = $("login-screen");
  const appMain = $("app-main");
  const loginForm = $("login-form");
  const loginUser = $("login-user");
  const loginPass = $("login-pass");

  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabViews = document.querySelectorAll(".tab-view");

  async function apiCall(endpoint, method = "GET", body = null, opts = {}) {
    const headers = { "Content-Type": "application/json" };
    if (sessionToken) headers["X-Admin-Token"] = sessionToken;
    const fetchOpts = { method, headers };
    if (body) fetchOpts.body = JSON.stringify(body);
    const res = await fetch(endpoint, fetchOpts);
    let json = null;
    try { json = await res.json(); } catch { json = {}; }
    if (!res.ok) {
      if (res.status === 401 && !opts.allowAuthRetry) {
        showLogin();
      }
      throw new Error(json.message || json.error || `HTTP ${res.status}`);
    }
    return json;
  }

  function showLogin() {
    sessionToken = "";
    localStorage.removeItem("secureit_session");
    loginScreen.classList.remove("hidden");
    appMain.classList.add("hidden");
    loginUser.value = "";
    loginPass.value = "";
    loginUser.focus();
  }

  function showApp() {
    loginScreen.classList.add("hidden");
    appMain.classList.remove("hidden");
    $("account-user").textContent = username;
    loadAllData();
  }

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUser.value.trim(), password: loginPass.value })
      });
      const data = await res.json();
      if (!res.ok) { showToast(data.message || "Credenciales inválidas", "error"); return; }
      sessionToken = data.session_token;
      username = data.username;
      localStorage.setItem("secureit_session", sessionToken);
      showApp();
    } catch (err) { showToast(err.message, "error"); }
  });

  $("btn-logout").addEventListener("click", async () => {
    try { await apiCall("/api/auth/logout", "POST", {}, { allowAuthRetry: true }); } catch {}
    showLogin();
  });

  $("btn-account").addEventListener("click", () => showModal($("modal-account")));
  $("btn-close-account").addEventListener("click", () => hideModal($("modal-account")));
  $("btn-cancel-account").addEventListener("click", () => hideModal($("modal-account")));
  $("form-password").addEventListener("submit", async (e) => {
    e.preventDefault();
    const cur = $("pw-current").value, nw = $("pw-new").value, cf = $("pw-confirm").value;
    if (nw !== cf) { showToast("Las contraseñas nuevas no coinciden", "error"); return; }
    try {
      await apiCall("/api/auth/change-password", "POST", { current_password: cur, new_password: nw });
      showToast("Contraseña actualizada", "success");
      hideModal($("modal-account"));
      $("form-password").reset();
    } catch (err) { showToast(err.message, "error"); }
  });

  $("btn-refresh").addEventListener("click", () => loadAllData());
  tabBtns.forEach((btn) => btn.addEventListener("click", () => {
    tabBtns.forEach((b) => b.classList.remove("active"));
    tabViews.forEach((v) => v.classList.remove("active"));
    btn.classList.add("active");
    const v = document.getElementById(`tab-view-${btn.dataset.tab}`);
    if (v) v.classList.add("active");
  }));

  // Filters
  $("search-servers").addEventListener("input", renderServers);
  $("filter-server-env").addEventListener("change", renderServers);
  $("filter-server-state").addEventListener("change", renderServers);
  $("search-creds").addEventListener("input", renderCredentials);
  $("filter-cred-env").addEventListener("change", renderCredentials);
  $("filter-cred-type").addEventListener("change", renderCredentials);
  $("search-tokens").addEventListener("input", renderTokens);
  $("search-audit").addEventListener("input", renderAudit);

  // Modals wiring
  wireModal("modal-add-server", "btn-open-add-server", "btn-close-add-server", "btn-cancel-add-server", "form-add-server", handleAddServer);
  wireModal("modal-import", "btn-open-import", "btn-close-import", "btn-cancel-import", "form-import", handleImport);
  wireModal("modal-token", "btn-open-token", "btn-close-token", "btn-cancel-token", "form-token", handleCreateToken);

  $("btn-copy-token").addEventListener("click", () => copyText($("token-raw-text").textContent, "Token copiado"));
  $("btn-add-grant").addEventListener("click", handleAddGrant);
  $("btn-close-grants").addEventListener("click", () => hideModal($("modal-grants")));
  $("btn-finish-grants").addEventListener("click", () => hideModal($("modal-grants")));

  // Reveal modal
  $("btn-close-reveal").addEventListener("click", closeRevealModal);
  $("btn-finish-reveal").addEventListener("click", closeRevealModal);
  $("btn-confirm-reveal").addEventListener("click", handleConfirmReveal);
  $("btn-hide-secret").addEventListener("click", hideSecretBox);
  $("btn-copy-secret").addEventListener("click", () => copyText($("reveal-secret-text").textContent, "Secreto copiado"));

  function wireModal(modalId, openBtn, closeBtn, cancelBtn, formId, onSubmit) {
    const modal = $(modalId);
    $(openBtn).addEventListener("click", () => showModal(modal));
    $(closeBtn).addEventListener("click", () => hideModal(modal));
    $(cancelBtn).addEventListener("click", () => hideModal(modal));
    if (formId && onSubmit) $(formId).addEventListener("submit", (e) => { e.preventDefault(); onSubmit(modal); });
  }

  function showModal(el) { el.classList.remove("hidden"); }
  function hideModal(el) { el.classList.add("hidden"); }

  function copyText(text, msg) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => showToast(msg, "success"));
  }

  // ── Init auth state ──
  (async function init() {
    if (!sessionToken) { showLogin(); return; }
    try {
      const me = await apiCall("/api/auth/me", "GET", null, { allowAuthRetry: true });
      username = me.username || "admin";
      showApp();
    } catch { showLogin(); }
  })();

  async function loadAllData() {
    if (!sessionToken) return;
    try {
      const [servers, creds, audits, tokensData] = await Promise.all([
        apiCall("/api/servers"),
        apiCall("/api/credentials"),
        apiCall("/api/audit-events"),
        apiCall("/api/tokens").catch(() => ({ tokens: [], general_id: null }))
      ]);
      serversCache = (servers && servers.servers) ? servers.servers : (servers || []);
      credentialsCache = creds || [];
      auditCache = audits || [];
      tokensCache = (tokensData && tokensData.tokens) || [];
      generalTokenId = (tokensData && tokensData.general_id) || null;
      renderServers(); renderCredentials(); renderTokens(); renderAudit(); updateStats();
    } catch (err) { showToast(err.message, "error"); }
  }

  function updateStats() {
    $("stat-servers").textContent = String(serversCache.length);
    $("stat-total").textContent = String(credentialsCache.length);
    $("stat-active").textContent = String(credentialsCache.filter((c) => c.status === "active").length);
    $("stat-rotated").textContent = String(credentialsCache.filter((c) => c.status === "rotated").length);
    $("stat-tokens").textContent = String(tokensCache.filter((t) => t.active).length);
    $("stat-audit").textContent = String(auditCache.length);
  }

  // ── RENDER: Servers ──
  function renderServers() {
    const tbody = $("servers-tbody"); tbody.replaceChildren();
    const q = $("search-servers").value.toLowerCase().trim();
    const env = $("filter-server-env").value, state = $("filter-server-state").value;
    const filtered = serversCache.filter((s) => {
      if (env && s.environment !== env) return false;
      if (state && s.lifecycleState !== state) return false;
      if (q) {
        const ok = s.name.toLowerCase().includes(q) || (s.endpoint?.address || "").toLowerCase().includes(q);
        if (!ok) return false;
      }
      return true;
    });
    if (filtered.length === 0) { emptyRow(tbody, 8, "No hay servidores."); return; }
    filtered.forEach((s) => {
      const tr = document.createElement("tr");
      tr.appendChild(tdStrong(s.name));
      tr.appendChild(tdText(s.endpoint ? `${s.endpoint.address}:${s.endpoint.port}` : "-"));
      tr.appendChild(tdBadge(s.connectionMode, "info"));
      tr.appendChild(tdBadge(s.environment, s.environment === "prod" ? "danger" : "warning"));
      tr.appendChild(tdText(s.owner || "admin")));
      tr.appendChild(tdText(tokenLabel(s.ownerTokenId)));
      const stTd = document.createElement("td");
      const dot = document.createElement("span");
      dot.className = "status-dot " + (s.lifecycleState === "managed" ? "green" : "yellow");
      const txt = document.createElement("span"); txt.style.marginLeft = "0.4rem"; txt.textContent = s.lifecycleState;
      stTd.appendChild(dot); stTd.appendChild(txt); tr.appendChild(stTd);
      const ac = document.createElement("td"); ac.style.textAlign = "right";
      const acts = document.createElement("div"); acts.className = "actions-cell";
      const bPerm = document.createElement("button"); bPerm.className = "btn btn-secondary btn-sm"; bPerm.textContent = "🔓 Permisos";
      bPerm.addEventListener("click", () => openGrantsModal(s));
      acts.appendChild(bPerm);
      const bDel = document.createElement("button"); bDel.className = "btn btn-danger btn-sm"; bDel.textContent = "🗑️";
      bDel.addEventListener("click", () => handleRemoveServer(s.id));
      acts.appendChild(bDel);
      ac.appendChild(acts); tr.appendChild(ac);
      tbody.appendChild(tr);
    });
  }

  function tokenLabel(tokenId) {
    if (!tokenId) return "—";
    const t = tokensCache.find((x) => x.id === tokenId);
    return t ? t.name : tokenId.slice(0, 8);
  }

  // ── RENDER: Credentials ──
  function renderCredentials() {
    const tbody = $("credentials-tbody"); tbody.replaceChildren();
    const q = $("search-creds").value.toLowerCase().trim();
    const env = $("filter-cred-env").value, type = $("filter-cred-type").value;
    const filtered = credentialsCache.filter((c) => {
      if (env && c.environment !== env) return false;
      if (type && c.type !== type) return false;
      if (q) { if (!(c.alias.toLowerCase().includes(q) || c.owner.toLowerCase().includes(q))) return false; }
      return true;
    });
    if (filtered.length === 0) { emptyRow(tbody, 9, "No hay credenciales."); return; }
    filtered.forEach((c) => {
      const tr = document.createElement("tr");
      tr.appendChild(tdStrong(c.alias));
      tr.appendChild(tdBadge(c.type, "info"));
      tr.appendChild(tdText(c.owner));
      tr.appendChild(tdBadge(c.environment, c.environment === "prod" ? "danger" : "warning"));
      tr.appendChild(tdBadge(c.status, c.status === "active" ? "success" : c.status === "rotated" ? "warning" : "danger"));
      tr.appendChild(tdText(`v${c.version}`));
      tr.appendChild(tdText(c.lastRotatedAt ? new Date(c.lastRotatedAt).toLocaleString() : "-"));
      tr.appendChild(tdBadge(c.exportable ? "Exportable" : "No exp.", c.exportable ? "purple" : "secondary"));
      const ac = document.createElement("td"); ac.style.textAlign = "right";
      const acts = document.createElement("div"); acts.className = "actions-cell";
      if (c.exportable) { const b = btn("👁️", "warning", () => openRevealModal(c.id)); acts.appendChild(b); }
      acts.appendChild(btn("🔄", "primary", () => handleRotate(c.id)));
      acts.appendChild(btn("🧪", "secondary", () => handleTest(c.id)));
      if (c.status !== "revoked") acts.appendChild(btn("🚫", "danger", () => handleRevoke(c.id)));
      ac.appendChild(acts); tr.appendChild(ac);
      tbody.appendChild(tr);
    });
  }

  // ── RENDER: Tokens ──
  function renderTokens() {
    const tbody = $("tokens-tbody"); tbody.replaceChildren();
    const q = $("search-tokens").value.toLowerCase().trim();
    const filtered = tokensCache.filter((t) => !q || t.name.toLowerCase().includes(q));
    if (filtered.length === 0) { emptyRow(tbody, 6, "No hay tokens. Crea uno con + Crear Token."); return; }
    filtered.forEach((t) => {
      const tr = document.createElement("tr");
      tr.appendChild(tdStrong(t.name));
      tr.appendChild(tdText(t.subject || "—"));
      tr.appendChild(tdBadge(t.is_general ? "general" : "session", t.is_general ? "purple" : "info"));
      tr.appendChild(tdBadge(t.active ? "activo" : "inactivo", t.active ? "success" : "secondary"));
      tr.appendChild(tdText(t.created_at ? new Date(t.created_at).toLocaleString() : "-"));
      const ac = document.createElement("td"); ac.style.textAlign = "right";
      if (!t.is_general) {
        const acts = document.createElement("div"); acts.className = "actions-cell";
        acts.appendChild(btn(t.active ? "⏸️" : "▶️", "secondary", () => handleToggleToken(t)));
        acts.appendChild(btn("🗑️", "danger", () => handleDeleteToken(t)));
        ac.appendChild(acts);
      } else {
        const fixed = document.createElement("span"); fixed.className = "badge secondary"; fixed.textContent = "fijo";
        ac.appendChild(fixed);
      }
      tr.appendChild(ac);
      tbody.appendChild(tr);
    });
  }

  // ── RENDER: Audit ──
  function renderAudit() {
    const tbody = $("audit-tbody"); tbody.replaceChildren();
    const q = $("search-audit").value.toLowerCase().trim();
    const filtered = auditCache.filter((a) => !q || (a.operation||"").toLowerCase().includes(q) || (a.subject||"").toLowerCase().includes(q) || (a.reasonCode||"").toLowerCase().includes(q));
    if (filtered.length === 0) { emptyRow(tbody, 6, "No hay eventos."); return; }
    [...filtered].reverse().slice(0, 50).forEach((ev) => {
      const tr = document.createElement("tr");
      tr.appendChild(tdText(new Date(ev.occurredAt).toLocaleString()));
      tr.appendChild(tdBadge(ev.operation, ev.operation.includes("reveal") ? "warning" : "info"));
      tr.appendChild(tdText(ev.subject));
      tr.appendChild(tdBadge(ev.outcome, ev.outcome === "allowed" ? "success" : "danger"));
      tr.appendChild(tdText((ev.objectIds || []).join(", ") || "-"));
      tr.appendChild(tdText(ev.reasonCode));
      tbody.appendChild(tr);
    });
  }

  // ── Handlers ──
  async function handleAddServer(modal) {
    const payload = {
      name: $("server-name").value.trim(),
      environment: $("server-env").value,
      owner: $("server-owner").value.trim() || "admin"
    };
    const u = $("server-username").value.trim(), p = $("server-password").value.trim();
    if (u) payload.username = u; if (p) payload.password = p;
    try {
      await apiCall("/api/servers", "POST", payload);
      showToast("Servidor registrado", "success");
      $("form-add-server").reset(); hideModal(modal); loadAllData();
    } catch (err) { showToast(err.message, "error"); }
  }

  async function handleRemoveServer(id) {
    if (!confirm("¿Eliminar este servidor?")) return;
    try { await apiCall(`/api/servers/${id}`, "DELETE"); showToast("Eliminado", "success"); loadAllData(); }
    catch (err) { showToast(err.message, "error"); }
  }

  async function handleImport(modal) {
    const payload = {
      alias: $("import-alias").value.trim(),
      type: $("import-type").value,
      owner: $("import-owner").value.trim(),
      environment: $("import-env").value,
      exportable: $("import-exportable").checked,
      secretValue: $("import-secret").value.trim()
    };
    try {
      await apiCall("/api/credentials", "POST", payload);
      showToast("Credencial guardada", "success");
      $("form-import").reset(); hideModal(modal); loadAllData();
    } catch (err) { showToast(err.message, "error"); }
  }

  async function handleCreateToken(modal) {
    const name = $("token-name").value.trim();
    if (!name) { showToast("Indica un nombre", "error"); return; }
    try {
      const res = await apiCall("/api/tokens", "POST", { name });
      $("token-raw-text").textContent = res.raw_token || "";
      $("token-raw-box").classList.remove("hidden");
      showToast("Token creado. Cópioalo ahora.", "success");
      $("token-name").value = "";
      loadAllData();
    } catch (err) { showToast(err.message, "error"); }
  }

  async function handleToggleToken(t) {
    try { await apiCall(`/api/tokens/${t.id}`, "PATCH", { active: !t.active }); showToast(t.active ? "Token desactivado" : "Token activado", "success"); loadAllData(); }
    catch (err) { showToast(err.message, "error"); }
  }

  async function handleDeleteToken(t) {
    if (!confirm(`¿Eliminar el token '${t.name}'? Los servidores que agregó quedarán sin dueño accesible solo por el admin.`)) return;
    try { await apiCall(`/api/tokens/${t.id}`, "DELETE"); showToast("Token eliminado", "success"); loadAllData(); }
    catch (err) { showToast(err.message, "error"); }
  }

  // ── Grants modal ──
  let currentGrantsServer = null;
  async function openGrantsModal(server) {
    currentGrantsServer = server;
    $("grants-server-name").textContent = `${server.name} (${server.environment})`;
    showModal($("modal-grants"));
    try {
      const data = await apiCall(`/api/servers/${server.id}/grants`);
      // poblar select con todos los tokens (incluye general)
      const sel = $("grant-token-select"); sel.replaceChildren();
      data.tokens.forEach((t) => {
        const opt = document.createElement("option"); opt.value = t.id;
        opt.textContent = `${t.name}${t.active ? "" : " (inactivo)"}`;
        sel.appendChild(opt);
      });
      renderGrants(data.grants);
    } catch (err) { showToast(err.message, "error"); }
  }

  function renderGrants(grants) {
    const tbody = $("grants-tbody"); tbody.replaceChildren();
    if (currentGrantsServer) {
      const ownerTr = document.createElement("tr");
      ownerTr.appendChild(tdText(tokenLabel(currentGrantsServer.ownerTokenId) + " (dueño)"));
      ownerTr.appendChild(tdBadge("dueño", "purple"));
      ownerTr.appendChild(tdText("—")); ownerTr.appendChild(tdText(""));
      tbody.appendChild(ownerTr);
    }
    if (!grants || grants.length === 0) { emptyRow(tbody, 4, "Sin permisos extendidos."); return; }
    grants.forEach((g) => {
      const tr = document.createElement("tr");
      tr.appendChild(tdText(tokenLabel(g.tokenId)));
      tr.appendChild(tdText("extendido"));
      tr.appendChild(tdText(g.grantedBy || "—"));
      const ac = tdText(""); ac.style.textAlign = "right";
      const b = btn("✕", "danger", () => handleRevokeGrant(g.tokenId));
      ac.replaceChildren(b); tr.appendChild(ac);
      tbody.appendChild(tr);
    });
  }

  async function handleAddGrant() {
    if (!currentGrantsServer) return;
    const tokenId = $("grant-token-select").value;
    if (!tokenId) return;
    try {
      await apiCall(`/api/servers/${currentGrantsServer.id}/grants`, "POST", { token_id: tokenId });
      showToast("Permiso concedido", "success");
      const data = await apiCall(`/api/servers/${currentGrantsServer.id}/grants`);
      renderGrants(data.grants);
    } catch (err) { showToast(err.message, "error"); }
  }

  async function handleRevokeGrant(tokenId) {
    if (!currentGrantsServer) return;
    try {
      await apiCall(`/api/servers/${currentGrantsServer.id}/grants/${tokenId}`, "DELETE");
      showToast("Permiso revocado", "success");
      const data = await apiCall(`/api/servers/${currentGrantsServer.id}/grants`);
      renderGrants(data.grants);
    } catch (err) { showToast(err.message, "error"); }
  }

  // ── Credential actions ──
  async function handleRotate(id) {
    if (!confirm("¿Rotar credencial?")) return;
    try { await apiCall(`/api/credentials/${id}/rotate`, "POST"); showToast("Rotada", "success"); loadAllData(); }
    catch (err) { showToast(err.message, "error"); }
  }
  async function handleRevoke(id) {
    if (!confirm("¿Revocar credencial?")) return;
    try { await apiCall(`/api/credentials/${id}/revoke`, "POST"); showToast("Revocada", "success"); loadAllData(); }
    catch (err) { showToast(err.message, "error"); }
  }
  async function handleTest(id) {
    try { const r = await apiCall(`/api/credentials/${id}/test`, "POST"); if (r.ok) showToast("Prueba OK", "success"); }
    catch (err) { showToast(err.message, "error"); }
  }
  function openRevealModal(id) { revealingCred = id; $("reveal-reason").value = ""; hideSecretBox(); showModal($("modal-reveal")); }
  function closeRevealModal() { hideSecretBox(); hideModal($("modal-reveal")); revealingCred = null; }
  async function handleConfirmReveal() {
    if (!revealingCred) return;
    const reason = $("reveal-reason").value.trim();
    if (!reason) { alert("Especifica un motivo."); return; }
    try {
      const res = await apiCall(`/api/credentials/${revealingCred}/reveal`, "POST", { reason });
      $("reveal-secret-text").textContent = res.secretValue;
      $("reveal-secret-box").classList.remove("hidden");
      startRevealTimer(15);
    } catch (err) { showToast(err.message, "error"); }
  }
  function startRevealTimer(s) {
    if (revealTimer) clearInterval(revealTimer);
    let r = s; $("reveal-timer").textContent = `${r}s`;
    revealTimer = setInterval(() => { r -= 1; if (r <= 0) hideSecretBox(); else $("reveal-timer").textContent = `${r}s`; }, 1000);
  }
  function hideSecretBox() { if (revealTimer) clearInterval(revealTimer); $("reveal-secret-text").textContent = ""; $("reveal-secret-box").classList.add("hidden"); }

  // ── DOM helpers ──
  function tdText(text) { const td = document.createElement("td"); td.textContent = text ?? ""; return td; }
  function tdStrong(text) { const td = document.createElement("td"); const s = document.createElement("strong"); s.textContent = text; td.appendChild(s); return td; }
  function tdBadge(text, cls) { const td = document.createElement("td"); const b = document.createElement("span"); b.className = `badge ${cls}`; b.textContent = text; td.appendChild(b); return td; }
  function btn(label, cls, onClick) { const b = document.createElement("button"); b.className = `btn btn-${cls} btn-sm`; b.textContent = label; b.addEventListener("click", onClick); return b; }
  function emptyRow(tbody, span, msg) { const tr = document.createElement("tr"); const td = document.createElement("td"); td.setAttribute("colspan", String(span)); td.style.textAlign = "center"; td.style.color = "var(--text-muted)"; td.style.padding = "1.5rem"; td.textContent = msg; tr.appendChild(td); tbody.appendChild(tr); }

  function showToast(msg, type = "info") {
    const t = $("toast"); t.textContent = msg; t.className = `toast ${type}`;
    setTimeout(() => { t.className = "toast hidden"; }, 3500);
  }
})();