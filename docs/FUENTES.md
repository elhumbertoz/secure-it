# Fuentes técnicas

Fuentes primarias y guías de referencia que sustentan las decisiones. Deben
revisarse de nuevo al fijar versiones de producto para la implementación.

- [NIST SP 800-207, Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final): separación de decisión y aplicación de políticas, acceso por recurso y evaluación continua.
- [OWASP LLM06:2025, Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/): riesgos de funcionalidad, permisos y autonomía excesivos en agentes.
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html): centralización, alcance, rotación, auditoría y ciclo de vida de secretos.
- [SPIFFE Concepts](https://spiffe.io/docs/latest/spiffe/concepts/): identidades verificables de carga de trabajo, rotación y credenciales de corta duración sin secretos preinstalados.
- [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/): interfaz y autorización para entregar identidades a cargas verificadas.
- [Open Policy Agent](https://www.openpolicyagent.org/docs): separación entre la decisión de política y su aplicación mediante entradas y decisiones estructuradas.
- [Vault: secretos estáticos y dinámicos](https://developer.hashicorp.com/vault/tutorials/get-started/understand-static-dynamic-secrets): emisión y revocación de credenciales bajo demanda.
- [Vault: certificados SSH firmados](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates): uso de una CA y roles para certificados SSH con vida limitada.
- [MCP: herramientas](https://modelcontextprotocol.io/specification/2025-11-25/server/tools): descubrimiento, esquemas de entrada/salida y resultados estructurados de herramientas.
- [MCP: transportes](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports): requisitos de `stdio` y Streamable HTTP.
- [MCP: autorización](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization): OAuth, descubrimiento, alcance y validación de audiencia.
- [MCP: prácticas de seguridad](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices): prevención de token passthrough, SSRF, secuestro de sesión y otros riesgos de servidores MCP.

La mención de SPIFFE, OPA o Vault ilustra una implementación posible; no implica
que sean obligatorios. Servicios nativos de nube u otros productos son válidos si
mantienen la misma separación, mínimo privilegio, vida corta y auditabilidad.
