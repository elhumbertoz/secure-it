# Objetivos, requisitos y límites

## Objetivo

Permitir que un agente planifique inspecciones y cambios operativos sobre la
infraestructura, manteniendo las credenciales fuera de su frontera de confianza y
reduciendo el efecto de errores, alucinaciones, inyección de instrucciones o
compromiso del modelo.

## Definiciones

- **Agente de IA:** modelo y proceso orquestador que interpreta la intención y
  propone acciones. Se considera no confiable para custodiar secretos.
- **Plano de control:** API determinista que autentica, autoriza, solicita
  aprobaciones, registra y despacha trabajos.
- **Broker de credenciales:** única pieza del camino de ejecución que puede
  solicitar al gestor de secretos una capacidad de acceso. No expone operaciones
  de lectura al agente.
- **Ejecutor:** proceso no agentivo que ejecuta una acción aprobada. Es efímero,
  aislado y no acepta instrucciones fuera del contrato de la acción.
- **Objetivo:** servidor, clúster, cuenta o servicio administrado.
- **Credencial:** contraseña, clave privada, token, cookie, certificado de cliente
  o cualquier material que permita autenticarse.
- **Capacidad:** autorización limitada por identidad, objetivo, acción y tiempo.
- **Consola administrativa:** interfaz exclusivamente humana, separada de MCP y
  del agente, para gestionar el ciclo de vida de credenciales y realizar lecturas
  excepcionales de secretos exportables.

## Propiedades obligatorias

1. Ninguna credencial de infraestructura entra en el contexto del modelo.
2. No existe una herramienta `get_secret`, una consulta SQL equivalente ni un
   endpoint que el agente pueda usar para leer secretos.
3. El inventario y los secretos usan almacenes y permisos diferentes.
4. Toda solicitud usa una identidad humana y/o de carga verificable; no se usan
   tokens compartidos de larga duración.
5. La autorización se decide fuera del modelo y deniega por defecto.
6. Cada acción tiene esquema de parámetros, riesgo, privilegio máximo, tiempo,
   número máximo de objetivos y política de aprobación.
7. Producción no admite shell arbitraria como operación autónoma.
8. Las capacidades son de corta duración, ligadas al trabajo y no renovables por
   el agente.
9. El ejecutor no devuelve credenciales, variables de entorno completas ni
   archivos sensibles.
10. Solicitud, decisión, aprobación, ejecución y resultado dejan una cadena de
    auditoría correlacionada y resistente a alteraciones.
11. Existe revocación, parada global, caducidad de trabajos y acceso de emergencia
    exclusivamente humano.
12. El fallo de política, identidad, auditoría o gestor de secretos provoca un
    rechazo seguro; no una degradación a acceso abierto.
13. El agente puede solicitar una rotación, pero no proporcionar, elegir, leer ni
    recuperar el valor anterior o nuevo.
14. Un token temporal visible para una integración solo autoriza un trabajo
    concreto en el plano de control; nunca es una credencial reutilizable de un
    servidor.
15. Claude, Codex y otros agentes acceden únicamente mediante herramientas MCP
    con esquemas estrictos; el nombre del cliente o modelo nunca concede permisos.
16. Las descripciones y anotaciones MCP ayudan al cliente, pero la autorización se
    aplica nuevamente en el servidor y no depende de que el host pida confirmación.
17. La administración humana de credenciales usa otra aplicación, sesión,
    identidad y autorización. Ninguna sesión o permiso del agente puede invocar,
    automatizar ni heredar su operación de revelado o copia.

## Dos interfaces con capacidades diferentes

El sistema puede y debe ofrecer una consola para que un administrador autorizado
liste metadatos, agregue o importe credenciales, las sustituya, rote, revoque y
pruebe. Cuando exista una necesidad operativa legítima, también puede revelar o
copiar una credencial estática exportable. Esta capacidad no contradice el
objetivo: el humano y su estación administrativa pertenecen a una frontera de
confianza distinta de la del agente.

MCP puede solicitar operaciones **ciegas** como generar y asociar una credencial,
rotarla, probarla o revocarla; solo recibe estado y evidencia no sensible. No puede
aceptar como argumento una contraseña existente ni devolver un valor. Por tanto,
importar un secreto conocido y ver/copiar un secreto son operaciones exclusivas de
la consola. Raíces de CA, claves en HSM y material marcado como no exportable no se
revelan ni siquiera allí.

El alcance y los controles de esta interfaz se especifican en
[Interfaz administrativa de credenciales](10-interfaz-administrativa-credenciales.md).

## Fuera de alcance inicial

- Defensa autónoma sin supervisión en producción.
- Ejecución de comandos generados libremente por el modelo.
- Rotación automática de todas las credenciales heredadas desde el primer día.
- Almacenamiento de contraseñas en PostgreSQL, aunque estén cifradas por la misma
  aplicación.
- Acceso del modelo a consolas de nube con roles administrativos.
- Considerar la red interna como una frontera de confianza suficiente.

## Qué se puede y qué no se puede prometer

Se puede garantizar mediante aislamiento y control de interfaces que el modelo no
reciba material secreto. No se puede garantizar que un agente con poder funcional
ilimitado sea inofensivo: una shell `root` puede crear usuarios, modificar acceso,
leer secretos presentes en el objetivo o destruir datos aun sin conocer la clave
con la que llegó.

Por tanto, la propiedad completa es:

> El agente no conoce credenciales y solo puede solicitar capacidades mínimas para
> acciones previamente definidas, sujetas a política y auditoría.

## Criterios de éxito

- Un volcado completo del proceso del agente no contiene secretos de objetivos.
- Una toma de control del agente no permite consultar el gestor de secretos.
- Una solicitud fuera del catálogo o con parámetros inválidos se rechaza antes de
  crear un trabajo.
- Una acción de producción que cambia estado no se ejecuta sin la aprobación
  requerida.
- El compromiso de un ejecutor afecta como máximo un trabajo, sus objetivos
  autorizados y el periodo de vida de su capacidad.
- Cada cambio puede atribuirse a usuario, sesión, versión del modelo, acción,
  versión de política, aprobador, ejecutor y objetivos exactos.
