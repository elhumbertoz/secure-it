# Ejecución ciega y capacidades temporales

## Qué significa “ciega”

La ejecución ciega permite que una persona o agente solicite una tarea sin conocer
la credencial del servidor. No significa que el plano de control desconozca la
acción o que acepte cualquier texto sin restricciones.

Hay dos niveles:

### Nivel A: acción tipada — recomendado

El solicitante elige `service.restart@2`, objetivo y parámetros permitidos. La
implementación, usuario remoto y mecanismo de acceso están revisados previamente.
Puede autorizarse de forma autónoma en contextos de bajo riesgo.

### Nivel B: comando o script sellado — excepcional

Permite enviar un comando/script conocido por el solicitante pero ejecutar la
conexión sin revelar credenciales. Como un shell es un lenguaje de propósito
general, este nivel se considera equivalente al máximo privilegio que posea el rol
remoto. Requiere:

- usuario autorizado y MFA reciente;
- objetivo exacto, sin selectores abiertos;
- análisis y vista previa del script;
- aprobación humana independiente en producción;
- rol remoto restringido, duración y fan-out mínimos;
- entorno no interactivo, sin reenvío ni túneles;
- red de salida bloqueada por defecto;
- artefacto inmutable firmado por hash;
- grabación y auditoría de entrada, salida y cambios;
- sin ejecución autónoma encadenada a partir de su resultado.

En el piloto, el Nivel B se limita a `dev/test`. No se ofrece una shell interactiva
al agente.

## Diseño de la capacidad temporal

La capacidad autoriza al portador únicamente a crear o consumir un trabajo. Debe
contener o referenciar:

- emisor y audiencia exactos;
- identidad del solicitante y sesión;
- `request_id` y hash del manifiesto;
- acción o digest del script;
- objetivos exactos;
- privilegio y adaptador permitidos;
- instante de emisión, no-antes-de y expiración;
- nonce y máximo de usos;
- hash de política y aprobación.

Debe estar ligada a una clave de la integración o canal mTLS cuando sea posible,
para que copiar el token no baste para usarlo. El adaptador conserva la sesión
fuera del prompt. El agente ve `request_id` y estado, no el valor del token.

El ejecutor se autentica por su propia identidad de carga y presenta el manifiesto
firmado. El broker verifica nuevamente acción, objetivos, caducidad y consumo antes
de emitir la credencial específica del servidor.

## Flujo

1. El solicitante crea una acción tipada o sube un script sellado.
2. El plano de control normaliza, calcula el digest y resuelve destinos.
3. Política determina rol, límites, canario y aprobaciones.
4. La aprobación firma el digest exacto; cualquier cambio obliga a repetirla.
5. Se emite un grant de uso único al ejecutor, no una clave SSH al solicitante.
6. El ejecutor pide al broker una capacidad del objetivo con TTL menor o igual al
   tiempo restante del trabajo.
7. El transporte autentica y ejecuta sin exponer la credencial al plugin hijo.
8. Se corta red y proceso al vencer el plazo; se revoca la capacidad y destruye el
   entorno.
9. La salida se clasifica, limita y filtra antes de mostrarse.

## Controles de salida

Aunque la credencial de conexión esté oculta, el comando podría leer otros
secretos presentes en el servidor. Por eso:

- el rol remoto no debe tener acceso general a archivos secretos;
- los plugins tipados solo devuelven campos definidos;
- el script sellado no tiene Internet salvo excepción aprobada;
- se bloquean rutas y operaciones sensibles mediante permisos del sistema, no
  solamente búsqueda de palabras;
- detectores de secretos bloquean y generan incidente ante una fuga probable;
- el agente no puede usar automáticamente una salida para crear otro trabajo.

La redacción posterior es una defensa adicional, no una garantía suficiente.

## Qué no implementar

- un endpoint `POST /run` que acepte `{host, command}` y use una clave root global;
- un token bearer reutilizable para cualquier servidor;
- una clave SSH montada junto al proceso del LLM;
- `SSH_AUTH_SOCK` accesible al comando o al contenedor del agente;
- secretos pasados en prompt, cabeceras visibles, `argv`, variables de entorno o
  archivos temporales persistentes;
- aprobaciones que no estén vinculadas al digest y a los destinos;
- comandos “permitidos” únicamente por regex o por evaluación del propio LLM.

## Criterio práctico

El modo ciego es seguro en la medida en que el sistema controla la capacidad, no
solo su representación textual. Si el rol remoto puede hacer todo como `root`, un
agente no necesita conocer la contraseña para causar un impacto total. Por ello la
reducción de privilegio del objetivo es tan importante como ocultar la credencial.
