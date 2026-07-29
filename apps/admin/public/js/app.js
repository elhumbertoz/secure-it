(function () {
  let adminToken = localStorage.getItem("secureit_admin_token") || "";
  let serversCache = [];
  let credentialsCache = [];
  let auditCache = [];
  let revealTimerInterval = null;
  let currentRevealingCredId = null;

  // DOM Elements
  const tokenInput = document.getElementById("admin-token-input");
  const btnSaveToken = document.getElementById("btn-save-token");
  const btnOpenAddServer = document.getElementById("btn-open-add-server");
  const btnOpenImport = document.getElementById("btn-open-import");
  const btnRefresh = document.getElementById("btn-refresh");

  // Tabs
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabViews = document.querySelectorAll(".tab-view");

  // Servers DOM
  const searchServers = document.getElementById("search-servers");
  const filterServerEnv = document.getElementById("filter-server-env");
  const filterServerState = document.getElementById("filter-server-state");
  const tbodyServers = document.getElementById("servers-tbody");

  // Credentials DOM
  const searchCreds = document.getElementById("search-creds");
  const filterCredEnv = document.getElementById("filter-cred-env");
  const filterCredType = document.getElementById("filter-cred-type");
  const tbodyCreds = document.getElementById("credentials-tbody");

  // Audit DOM
  const searchAudit = document.getElementById("search-audit");
  const tbodyAudit = document.getElementById("audit-tbody");

  // Stats DOM
  const statServers = document.getElementById("stat-servers");
  const statTotal = document.getElementById("stat-total");
  const statActive = document.getElementById("stat-active");
  const statRotated = document.getElementById("stat-rotated");
  const statAudit = document.getElementById("stat-audit");

  // Modals DOM
  const modalAddServer = document.getElementById("modal-add-server");
  const btnCloseAddServer = document.getElementById("btn-close-add-server");
  const btnCancelAddServer = document.getElementById("btn-cancel-add-server");
  const formAddServer = document.getElementById("form-add-server");

  const modalImport = document.getElementById("modal-import");
  const btnCloseImport = document.getElementById("btn-close-import");
  const btnCancelImport = document.getElementById("btn-cancel-import");
  const formImport = document.getElementById("form-import");

  const modalReveal = document.getElementById("modal-reveal");
  const btnCloseReveal = document.getElementById("btn-close-reveal");
  const btnFinishReveal = document.getElementById("btn-finish-reveal");
  const revealReason = document.getElementById("reveal-reason");
  const btnConfirmReveal = document.getElementById("btn-confirm-reveal");
  const secretBox = document.getElementById("reveal-secret-box");
  const revealTimer = document.getElementById("reveal-timer");
  const revealSecretText = document.getElementById("reveal-secret-text");
  const btnCopySecret = document.getElementById("btn-copy-secret");
  const btnHideSecret = document.getElementById("btn-hide-secret");

  const toast = document.getElementById("toast");

  // Init Token
  if (adminToken) {
    tokenInput.value = adminToken;
  } else {
    fetch("/api/auth/token")
      .then((r) => r.json())
      .then((data) => {
        if (data.token) {
          adminToken = data.token;
          tokenInput.value = adminToken;
          loadAllData();
        }
      })
      .catch(() => {});
  }

  // Event Listeners - Save Token & Refresh
  btnSaveToken.addEventListener("click", () => {
    adminToken = tokenInput.value.trim();
    localStorage.setItem("secureit_admin_token", adminToken);
    showToast("Token de administración guardado", "success");
    loadAllData();
  });

  btnRefresh.addEventListener("click", () => loadAllData());

  // Tab Switcher
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      tabViews.forEach((v) => v.classList.remove("active"));

      btn.classList.add("active");
      const targetId = `tab-view-${btn.dataset.tab}`;
      const targetView = document.getElementById(targetId);
      if (targetView) targetView.classList.add("active");
    });
  });

  // Filter Listeners
  searchServers.addEventListener("input", () => renderServers());
  filterServerEnv.addEventListener("change", () => renderServers());
  filterServerState.addEventListener("change", () => renderServers());

  searchCreds.addEventListener("input", () => renderCredentials());
  filterCredEnv.addEventListener("change", () => renderCredentials());
  filterCredType.addEventListener("change", () => renderCredentials());

  searchAudit.addEventListener("input", () => renderAudit());

  // Modals Listeners
  btnOpenAddServer.addEventListener("click", () => showModal(modalAddServer));
  btnCloseAddServer.addEventListener("click", () => hideModal(modalAddServer));
  btnCancelAddServer.addEventListener("click", () => hideModal(modalAddServer));
  formAddServer.addEventListener("submit", handleAddServerSubmit);

  btnOpenImport.addEventListener("click", () => showModal(modalImport));
  btnCloseImport.addEventListener("click", () => hideModal(modalImport));
  btnCancelImport.addEventListener("click", () => hideModal(modalImport));
  formImport.addEventListener("submit", handleImportSubmit);

  btnCloseReveal.addEventListener("click", () => closeRevealModal());
  btnFinishReveal.addEventListener("click", () => closeRevealModal());
  btnConfirmReveal.addEventListener("click", handleConfirmReveal);
  btnHideSecret.addEventListener("click", () => hideSecretBox());
  btnCopySecret.addEventListener("click", handleCopySecret);

  // Initial Load
  loadAllData();

  // API Call Helper
  async function apiCall(endpoint, method = "GET", body = null) {
    const headers = { "Content-Type": "application/json" };
    if (adminToken) headers["X-Admin-Token"] = adminToken;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(endpoint, opts);
    const json = await res.json();

    if (!res.ok) {
      throw new Error(json.message || json.error || `HTTP ${res.status}`);
    }
    return json;
  }

  // Loaders
  async function loadAllData() {
    try {
      const [serversRes, credsRes, auditsRes] = await Promise.all([
        apiCall("/api/servers"),
        apiCall("/api/credentials"),
        apiCall("/api/audit-events")
      ]);

      serversCache = serversRes.servers || [];
      credentialsCache = credsRes || [];
      auditCache = auditsRes || [];

      renderServers();
      renderCredentials();
      renderAudit();
      updateStats();
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  function updateStats() {
    statServers.textContent = String(serversCache.length);
    statTotal.textContent = String(credentialsCache.length);
    statActive.textContent = String(credentialsCache.filter((c) => c.status === "active").length);
    statRotated.textContent = String(credentialsCache.filter((c) => c.status === "rotated").length);
    statAudit.textContent = String(auditCache.length);
  }

  // 1. Render Servers
  function renderServers() {
    tbodyServers.replaceChildren();

    const q = searchServers.value.toLowerCase().trim();
    const env = filterServerEnv.value;
    const state = filterServerState.value;

    const filtered = serversCache.filter((s) => {
      if (env && s.environment !== env) return false;
      if (state && s.lifecycleState !== state) return false;
      if (q) {
        const nameMatch = s.name.toLowerCase().includes(q);
        const addrMatch = (s.endpoint?.address || "").toLowerCase().includes(q);
        if (!nameMatch && !addrMatch) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.setAttribute("colspan", "8");
      td.style.textAlign = "center";
      td.style.color = "var(--text-muted)";
      td.style.padding = "2rem";
      td.textContent = "No hay servidores registrados que coincidan con la búsqueda.";
      tr.appendChild(td);
      tbodyServers.appendChild(tr);
      return;
    }

    filtered.forEach((srv) => {
      const tr = document.createElement("tr");

      // Name
      const tdName = document.createElement("td");
      const strongName = document.createElement("strong");
      strongName.textContent = srv.name;
      tdName.appendChild(strongName);
      tr.appendChild(tdName);

      // Endpoint
      const tdEndpoint = document.createElement("td");
      const epText = srv.endpoint ? `${srv.endpoint.address}:${srv.endpoint.port}` : "-";
      tdEndpoint.textContent = epText;
      tr.appendChild(tdEndpoint);

      // Connection Mode
      const tdMode = document.createElement("td");
      const badgeMode = document.createElement("span");
      badgeMode.className = "badge info";
      badgeMode.textContent = srv.connectionMode;
      tdMode.appendChild(badgeMode);
      tr.appendChild(tdMode);

      // Environment
      const tdEnv = document.createElement("td");
      const badgeEnv = document.createElement("span");
      badgeEnv.className = "badge " + (srv.environment === "prod" ? "danger" : "warning");
      badgeEnv.textContent = srv.environment;
      tdEnv.appendChild(badgeEnv);
      tr.appendChild(tdEnv);

      // Owner
      const tdOwner = document.createElement("td");
      tdOwner.textContent = srv.owner || "admin";
      tr.appendChild(tdOwner);

      // Criticality
      const tdCrit = document.createElement("td");
      const badgeCrit = document.createElement("span");
      badgeCrit.className = "badge " + (srv.criticality === "critical" || srv.criticality === "high" ? "danger" : "secondary");
      badgeCrit.textContent = srv.criticality;
      tdCrit.appendChild(badgeCrit);
      tr.appendChild(tdCrit);

      // State
      const tdState = document.createElement("td");
      const stateDot = document.createElement("span");
      stateDot.className = "status-dot " + (srv.lifecycleState === "managed" ? "green" : "yellow");
      const stateText = document.createElement("span");
      stateText.style.marginLeft = "0.4rem";
      stateText.textContent = srv.lifecycleState;
      tdState.appendChild(stateDot);
      tdState.appendChild(stateText);
      tr.appendChild(tdState);

      // Actions
      const tdActions = document.createElement("td");
      tdActions.style.textAlign = "right";
      const btnRemove = document.createElement("button");
      btnRemove.className = "btn btn-danger btn-sm";
      btnRemove.textContent = "🗑️ Eliminar";
      btnRemove.addEventListener("click", () => handleRemoveServer(srv.id));
      tdActions.appendChild(btnRemove);
      tr.appendChild(tdActions);

      tbodyServers.appendChild(tr);
    });
  }

  // 2. Render Credentials
  function renderCredentials() {
    tbodyCreds.replaceChildren();

    const q = searchCreds.value.toLowerCase().trim();
    const env = filterCredEnv.value;
    const type = filterCredType.value;

    const filtered = credentialsCache.filter((c) => {
      if (env && c.environment !== env) return false;
      if (type && c.type !== type) return false;
      if (q) {
        const aliasMatch = c.alias.toLowerCase().includes(q);
        const ownerMatch = c.owner.toLowerCase().includes(q);
        if (!aliasMatch && !ownerMatch) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.setAttribute("colspan", "9");
      td.style.textAlign = "center";
      td.style.color = "var(--text-muted)";
      td.style.padding = "2rem";
      td.textContent = "No hay credenciales registradas que coincidan.";
      tr.appendChild(td);
      tbodyCreds.appendChild(tr);
      return;
    }

    filtered.forEach((cred) => {
      const tr = document.createElement("tr");

      // Alias
      const tdAlias = document.createElement("td");
      const strongAlias = document.createElement("strong");
      strongAlias.textContent = cred.alias;
      tdAlias.appendChild(strongAlias);
      tr.appendChild(tdAlias);

      // Type
      const tdType = document.createElement("td");
      const badgeType = document.createElement("span");
      badgeType.className = "badge info";
      badgeType.textContent = cred.type;
      tdType.appendChild(badgeType);
      tr.appendChild(tdType);

      // Owner
      const tdOwner = document.createElement("td");
      tdOwner.textContent = cred.owner;
      tr.appendChild(tdOwner);

      // Env
      const tdEnv = document.createElement("td");
      const badgeEnv = document.createElement("span");
      badgeEnv.className = "badge " + (cred.environment === "prod" ? "danger" : "warning");
      badgeEnv.textContent = cred.environment;
      tdEnv.appendChild(badgeEnv);
      tr.appendChild(tdEnv);

      // Status
      const tdStatus = document.createElement("td");
      const badgeStatus = document.createElement("span");
      badgeStatus.className = "badge " + (cred.status === "active" ? "success" : cred.status === "rotated" ? "warning" : "danger");
      badgeStatus.textContent = cred.status;
      tdStatus.appendChild(badgeStatus);
      tr.appendChild(tdStatus);

      // Version
      const tdVersion = document.createElement("td");
      tdVersion.textContent = `v${cred.version}`;
      tr.appendChild(tdVersion);

      // Last Rotated
      const tdRotated = document.createElement("td");
      tdRotated.textContent = cred.lastRotatedAt ? new Date(cred.lastRotatedAt).toLocaleString() : "-";
      tr.appendChild(tdRotated);

      // Exportable
      const tdExport = document.createElement("td");
      const badgeExport = document.createElement("span");
      badgeExport.className = "badge " + (cred.exportable ? "purple" : "secondary");
      badgeExport.textContent = cred.exportable ? "Exportable" : "No Exportable";
      tdExport.appendChild(badgeExport);
      tr.appendChild(tdExport);

      // Actions
      const tdActions = document.createElement("td");
      tdActions.style.textAlign = "right";
      const actionsDiv = document.createElement("div");
      actionsDiv.className = "actions-cell";

      if (cred.exportable) {
        const btnReveal = document.createElement("button");
        btnReveal.className = "btn btn-warning btn-sm";
        btnReveal.textContent = "👁️ Revelar";
        btnReveal.addEventListener("click", () => openRevealModal(cred.id));
        actionsDiv.appendChild(btnReveal);
      }

      const btnRotate = document.createElement("button");
      btnRotate.className = "btn btn-primary btn-sm";
      btnRotate.textContent = "🔄 Rotar";
      btnRotate.addEventListener("click", () => handleRotate(cred.id));
      actionsDiv.appendChild(btnRotate);

      const btnTest = document.createElement("button");
      btnTest.className = "btn btn-secondary btn-sm";
      btnTest.textContent = "🧪 Probar";
      btnTest.addEventListener("click", () => handleTest(cred.id));
      actionsDiv.appendChild(btnTest);

      if (cred.status !== "revoked") {
        const btnRevoke = document.createElement("button");
        btnRevoke.className = "btn btn-danger btn-sm";
        btnRevoke.textContent = "🚫 Revocar";
        btnRevoke.addEventListener("click", () => handleRevoke(cred.id));
        actionsDiv.appendChild(btnRevoke);
      }

      tdActions.appendChild(actionsDiv);
      tr.appendChild(tdActions);

      tbodyCreds.appendChild(tr);
    });
  }

  // 3. Render Audit
  function renderAudit() {
    tbodyAudit.replaceChildren();

    const q = searchAudit.value.toLowerCase().trim();

    const filtered = auditCache.filter((a) => {
      if (!q) return true;
      const opMatch = (a.operation || "").toLowerCase().includes(q);
      const subMatch = (a.subject || "").toLowerCase().includes(q);
      const reasonMatch = (a.reasonCode || "").toLowerCase().includes(q);
      return opMatch || subMatch || reasonMatch;
    });

    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.setAttribute("colspan", "6");
      td.style.textAlign = "center";
      td.style.color = "var(--text-muted)";
      td.style.padding = "1.5rem";
      td.textContent = "No hay eventos de auditoría que coincidan.";
      tr.appendChild(td);
      tbodyAudit.appendChild(tr);
      return;
    }

    const sorted = [...filtered].reverse().slice(0, 30);

    sorted.forEach((event) => {
      const tr = document.createElement("tr");

      const tdTime = document.createElement("td");
      tdTime.textContent = new Date(event.occurredAt).toLocaleString();
      tr.appendChild(tdTime);

      const tdOp = document.createElement("td");
      const badgeOp = document.createElement("span");
      badgeOp.className = "badge " + (event.operation.includes("reveal") ? "warning" : "info");
      badgeOp.textContent = event.operation;
      tdOp.appendChild(badgeOp);
      tr.appendChild(tdOp);

      const tdSub = document.createElement("td");
      tdSub.textContent = event.subject;
      tr.appendChild(tdSub);

      const tdOutcome = document.createElement("td");
      const badgeOutcome = document.createElement("span");
      badgeOutcome.className = "badge " + (event.outcome === "allowed" ? "success" : "danger");
      badgeOutcome.textContent = event.outcome;
      tdOutcome.appendChild(badgeOutcome);
      tr.appendChild(tdOutcome);

      const tdObjs = document.createElement("td");
      tdObjs.textContent = (event.objectIds || []).join(", ") || "-";
      tr.appendChild(tdObjs);

      const tdReason = document.createElement("td");
      tdReason.textContent = event.reasonCode;
      tr.appendChild(tdReason);

      tbodyAudit.appendChild(tr);
    });
  }

  // Handlers - Add Server
  async function handleAddServerSubmit(e) {
    e.preventDefault();
    const name = document.getElementById("server-name").value.trim();
    const username = document.getElementById("server-username").value.trim();
    const password = document.getElementById("server-password").value.trim();
    const environment = document.getElementById("server-env").value;
    const owner = document.getElementById("server-owner").value.trim() || "admin";

    const payload = { name, environment, owner };
    if (username) payload.username = username;
    if (password) payload.password = password;

    try {
      await apiCall("/api/servers", "POST", payload);
      showToast(`Servidor '${name}' registrado con éxito`, "success");
      formAddServer.reset();
      hideModal(modalAddServer);
      loadAllData();
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  async function handleRemoveServer(id) {
    if (!confirm("¿Estás seguro de eliminar este servidor de la infraestructura?")) return;
    try {
      await apiCall(`/api/servers/${id}`, "DELETE");
      showToast("Servidor eliminado", "success");
      loadAllData();
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  // Handlers - Import Credential
  async function handleImportSubmit(e) {
    e.preventDefault();
    const alias = document.getElementById("import-alias").value.trim();
    const type = document.getElementById("import-type").value;
    const owner = document.getElementById("import-owner").value.trim();
    const environment = document.getElementById("import-env").value;
    const exportable = document.getElementById("import-exportable").checked;
    const secretValue = document.getElementById("import-secret").value.trim();

    try {
      await apiCall("/api/credentials", "POST", {
        alias,
        type,
        owner,
        environment,
        exportable,
        secretValue
      });

      showToast(`Credencial '${alias}' guardada exitosamente`, "success");
      formImport.reset();
      hideModal(modalImport);
      loadAllData();
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  async function handleRotate(id) {
    if (!confirm("¿Confirmas la rotación ciega de la credencial?")) return;
    try {
      await apiCall(`/api/credentials/${id}/rotate`, "POST");
      showToast("Credencial rotada con éxito", "success");
      loadAllData();
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  async function handleRevoke(id) {
    if (!confirm("¿Estás seguro de revocar esta credencial?")) return;
    try {
      await apiCall(`/api/credentials/${id}/revoke`, "POST");
      showToast("Credencial revocada", "success");
      loadAllData();
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  async function handleTest(id) {
    try {
      const res = await apiCall(`/api/credentials/${id}/test`, "POST");
      if (res.ok) {
        showToast("Prueba de acceso OK (sin exponer secreto)", "success");
        loadAllData();
      }
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  // Reveal Modal
  function openRevealModal(id) {
    currentRevealingCredId = id;
    revealReason.value = "";
    hideSecretBox();
    showModal(modalReveal);
  }

  function closeRevealModal() {
    hideSecretBox();
    hideModal(modalReveal);
    currentRevealingCredId = null;
  }

  async function handleConfirmReveal() {
    if (!currentRevealingCredId) return;
    const reason = revealReason.value.trim();
    if (!reason) {
      alert("Por favor especifica un motivo de revelado para la auditoría.");
      return;
    }

    try {
      const res = await apiCall(`/api/credentials/${currentRevealingCredId}/reveal`, "POST", { reason });
      revealSecretText.textContent = res.secretValue;
      secretBox.classList.remove("hidden");
      startRevealTimer(15);
      loadAllData();
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  function startRevealTimer(seconds) {
    if (revealTimerInterval) clearInterval(revealTimerInterval);
    let remaining = seconds;
    revealTimer.textContent = `Auto-ocultado en ${remaining}s`;

    revealTimerInterval = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        hideSecretBox();
      } else {
        revealTimer.textContent = `Auto-ocultado en ${remaining}s`;
      }
    }, 1000);
  }

  function hideSecretBox() {
    if (revealTimerInterval) clearInterval(revealTimerInterval);
    revealSecretText.textContent = "";
    secretBox.classList.add("hidden");
  }

  function handleCopySecret() {
    const text = revealSecretText.textContent;
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      showToast("Secreto copiado al portapapeles.", "success");
    });
  }

  // Modal Helpers
  function showModal(el) { el.classList.remove("hidden"); }
  function hideModal(el) { el.classList.add("hidden"); }

  function showToast(msg, type = "info") {
    toast.textContent = msg;
    toast.className = `toast ${type}`;
    setTimeout(() => {
      toast.className = "toast hidden";
    }, 3500);
  }
})();
