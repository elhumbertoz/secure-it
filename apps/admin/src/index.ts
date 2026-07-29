#!/usr/bin/env node
import { createAdminServer } from "./server.js";
import { getAdminToken } from "./auth.js";

const port = Number(process.env.ADMIN_PORT || process.env.PORT || 4000);
const host = "127.0.0.1"; // Security requirement: Always listen on 127.0.0.1 for local admin

const { app } = createAdminServer();

app.listen(port, host, () => {
  const token = getAdminToken();
  console.log(`
===============================================================
🛡️  secure-it | Consola Administrativa Web de Credenciales
===============================================================
🌐 Servidor ejecutándose en: http://${host}:${port}
🔑 Token de Administración: ${token}
===============================================================
  `);
});
