# Plan de implementación y operación

## Fase 0: decisiones y preparación

1. Nombrar propietarios de plataforma, seguridad, inventario y auditoría.
2. Elegir el proveedor de identidad humana con MFA resistente a phishing.
3. Elegir el gestor de secretos/CA y la identidad de cargas de trabajo.
4. Definir ambientes, criticidad, etiquetas permitidas y matriz de riesgos.
5. Identificar cinco servidores no críticos para el piloto.
6. Aprobar el modelo de amenazas y las prohibiciones iniciales.
7. Inventariar toda credencial que haya aparecido en chats, prompts, trazas o
   herramientas de IA; revocarla, rotarla e investigar su uso antes del piloto.
8. Definir quién puede administrar, revelar y copiar cada clase de credencial, y
   qué material debe permanecer no exportable.

Entregable: decisiones registradas y ninguna credencial real todavía.

## Fase 1: inventario y canal administrativo

1. Desplegar PostgreSQL con roles separados, TLS, copias y auditoría.
2. Crear el esquema de inventario y la vista mínima para el agente.
3. Implementar altas con verificación de propietario e identidad del host.
4. Importar solo metadatos; detectar duplicados y datos incompletos.
5. Habilitar consultas del catálogo sin capacidad de ejecutar.
6. Implementar la consola administrativa separada con alta/importación, rotación,
   revocación y auditoría. Mantener el revelado deshabilitado hasta validar MFA
   reforzado, permisos por secreto y controles de sesión.

Salida: el agente puede identificar objetivos lógicos, pero no conoce endpoints de
administración ni bindings; los operadores disponen de un canal humano controlado
para cargar las credenciales heredadas necesarias.

## Fase 2: camino de ejecución de lectura

1. Implementar el servidor MCP remoto, OAuth, validación, idempotencia y
   manifiestos firmados.
2. Publicar las herramientas de inventario y ejecución de acciones; comprobarlas
   al menos con dos clientes MCP independientes.
3. Desplegar motor de políticas con denegación por defecto.
4. Desplegar cola y ejecutores aislados de un solo uso.
5. Preferir daemon local con identidad de carga; usar SSH CA efímera solo donde sea
   necesario.
6. Crear entre tres y cinco acciones de diagnóstico tipadas.
7. Implementar auditoría append-only, límites y filtrado de salida.
8. Ejecutar todas las pruebas negativas del modelo de amenazas.

Salida: diagnóstico autónomo solo en `dev/test`, sin shell libre.

## Fase 3: cambios de bajo riesgo

1. Añadir aprobación enlazada al hash del manifiesto.
2. Incorporar canario, límite de concurrencia, cancelación y reversión.
3. Añadir acciones idempotentes como reinicio de un servicio stateless de pruebas.
4. Ensayar caída de dependencias, trabajos atascados y recuperación.
5. Medir rechazos, falsos positivos, tiempo de aprobación y trazabilidad.

Salida: cambios supervisados en no producción.

## Fase 4: producción gradual

1. Revisión independiente de arquitectura, políticas y aislamiento.
2. Ejercicio de equipo rojo centrado en prompt injection, herramientas y broker.
3. Habilitar primero lectura en pocos objetivos de producción.
4. Exigir aprobador independiente para cambios y comenzar por un canario.
5. Ampliar acciones y objetivos solo con evidencia y revisión de riesgo.

IAM, raíces de confianza, destrucción, backup y cambios masivos permanecen fuera de
la autonomía hasta una decisión de seguridad específica.

## Operación continua

### Altas y bajas

Toda alta valida propietario, criticidad, huella/identidad y mecanismo de acceso.
Al retirar un servidor se revocan bindings, identidades y trabajos pendientes antes
de marcarlo `retired`. La reconciliación periódica alerta sobre recursos reales que
no están en inventario y registros que ya no existen.

### Rotación

- identidades de carga y certificados: automática y de corta duración;
- emisores intermedios: procedimiento ensayado con solapamiento;
- credenciales heredadas: rotación periódica y plan para eliminarlas;
- claves de firma de manifiestos y auditoría: separadas de las CA de acceso.

La rotación se prueba en no producción y dispone de reversión. Nunca se imprime el
nuevo valor en logs ni se pasa por el agente.

Una credencial expuesta no espera esta frecuencia: dispara rotación por evento,
revocación de sesiones y revisión inmediata. La programación periódica es una red
de seguridad, no la respuesta a una exposición conocida.

### Observabilidad y alertas

Alertar por denegaciones repetidas, selectores amplios, intentos de acceder al
broker, expiraciones anómalas, divergencia de inventario, cambios de identidad del
host, uso fuera de ventana, aprobaciones inusuales y detección de secretos en
salidas. Métricas y trazas deben usar identificadores, no parámetros sensibles.

### Acceso de emergencia

El mecanismo `break-glass` es humano, separado del agente, protegido con MFA fuerte
y, para producción crítica, con dos personas. Emite acceso corto, notifica de
inmediato y audita en un sistema que el usuario de emergencia no puede modificar.
Después se revocan sesiones, se rotan credenciales afectadas y se revisa el evento.

### Respuesta a incidentes

1. Activar parada global de nuevos trabajos.
2. Revocar identidades de ejecutores, sesiones y capacidades activas.
3. Aislar agente, broker o objetivos según el indicador.
4. Preservar auditoría, manifiestos y artefactos; no confiar en el historial del
   modelo como fuente única.
5. Determinar alcance por `request_id`, identidad, objetivos y ventana temporal.
6. Rotar material potencialmente expuesto y reconstruir ejecutores.
7. Reanudar por etapas después de corregir política o catálogo.

## Puertas de promoción

Antes de cada ambiente deben cumplirse todas:

- pruebas funcionales y negativas automatizadas;
- revisión de mínimo privilegio y separación de funciones;
- restauración de inventario y auditoría probada;
- revocación y parada global medidas;
- cero secretos en prompts, logs, trazas, fixtures e imágenes;
- artefactos fijados por digest y verificados;
- propietario y reversión para cada acción;
- simulacro reciente de incidente y `break-glass`.

## Preguntas que deben resolverse antes de implementar

- ¿Cuántos servidores hay y en qué nubes, redes y sistemas operativos?
- ¿Existe Kubernetes, un proveedor OIDC, TPM/HSM o identidad nativa de nube?
- ¿Qué mecanismos actuales se usan: SSH, WinRM, APIs, bastiones o VPN?
- ¿Qué acciones concretas debe poder realizar el agente durante el primer mes?
- ¿Qué se considera producción y quién puede aprobar cada nivel de riesgo?
- ¿Qué requisitos de residencia, retención, cumplimiento y recuperación existen?

Estas respuestas permiten elegir productos y dimensionar el piloto sin debilitar
las invariantes de seguridad.
