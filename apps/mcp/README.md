# @secure-it/mcp

Servidor MCP y consola local de `secure-it`:

```bash
npx -y @secure-it/mcp@beta
```

Este comando ahora:

- **Instala automáticamente todas las dependencias.**
- **Inicia el MCP por stdio** (listo para tu cliente de IA).
- **Inicia la consola administrativa** en `http://127.0.0.1:4000`.
- **Crea automáticamente la base de datos SQLite**.
- **Genera la clave maestra local** (`SECUREIT_MASTER_KEY`).
- **Protege la base de datos y la clave** con permisos `0600`.
- **Permite crear el administrador** desde la consola durante el primer acceso.

No requiere un proyecto Node preexistente, variables de entorno ni instalaciones o configuraciones adicionales.

Consulte la documentación completa y límites de seguridad en https://github.com/elhumbertoz/secure-it.
