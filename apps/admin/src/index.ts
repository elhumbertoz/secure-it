#!/usr/bin/env node
import { createAdminServer } from "./server.js";

const port = Number(process.env.ADMIN_PORT || process.env.PORT || 4000);
const host = "127.0.0.1"; // Security requirement: Always listen on 127.0.0.1 for local admin

const { app } = createAdminServer();

app.listen(port, host, () => {
  console.log(`
==============================================================
🛡️  secure-it | Consola Administrativa Web
==============================================================
🌐 http://${host}:${port}
👤 Acceso: usa la cuenta configurada durante el bootstrap
==============================================================
  `);
});
