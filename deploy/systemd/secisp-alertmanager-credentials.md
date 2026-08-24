# Credenciales de Alertmanager: dónde vive el token de Telegram

T-319 (E12a-T25, ola 8) -- E12 §4.7.1, E12 §3 D1.

Este archivo vive en `deploy/systemd/` por convención de ubicación (junto al
resto de la documentación de "cómo se instala cada pieza"), no porque
Alertmanager corra como unidad systemd: corre en contenedor
(`infra/docker-compose.yml`, T-034/T-319), igual que ClickHouse, Prometheus,
Grafana y node-exporter -- D1 (E12 §3) es la decisión que fija por qué esas
cinco piezas van en Docker y los cuatro roles de `secisp` van en systemd
nativo.

## La regla

**El token de Telegram nunca va en un archivo versionado.** `infra/
alertmanager/alertmanager.yml` referencia `bot_token_file:
/run/secrets/telegram_bot_token` -- una ruta *dentro* del contenedor que
Docker Compose arma a partir de un archivo *fuera* del repo.

`git grep -i "bot_token:" infra/` no debería encontrar nunca un valor que no
sea `bot_token_file`. Si alguna vez aparece un `bot_token: <valor>` directo
en un YAML versionado, es el mismo bug que el prototipo documentó con
`env_file` y comillas (D1, E12 §3): un secreto quedó en texto plano dentro
del historial de git, que no se limpia borrando el archivo después.

## Instalación (una vez, por host)

1. Crear el bot con [@BotFather](https://t.me/BotFather) en Telegram
   (`/newbot`), guardar el token que devuelve.
2. Crear (o reusar) el grupo/canal de Telegram del operador y agregar el
   bot.
3. Escribir el token en el host, **fuera del repo clonado o dentro de él
   pero bajo una ruta que `.gitignore` ya excluye**:

   ```bash
   mkdir -p infra/secrets
   printf '%s' '123456789:AAal9uh-el-token-real-sin-comillas-ni-prefijo' > infra/secrets/telegram_bot_token
   chmod 0600 infra/secrets/telegram_bot_token
   ```

   `infra/secrets/*` ya está en `.gitignore` (T-319) -- pero el paso 3
   sigue siendo responsabilidad del operador: nada en el repo puede crear
   este archivo por él sin comprometer el secreto en el proceso (un
   generador tendría que recibir el token como argumento, que reaparece en
   el historial de shell/CI).

4. `printf '%s'`, no `echo`: evita el salto de línea final que `echo`
   agrega por defecto y que un editor de texto (`vim`, `nano`) también
   podría agregar -- Alertmanager hace trim de whitespace del archivo, así
   que un salto de línea de más no rompe nada, pero **una comilla sí**
   (`'` o `"` alrededor del token) rompería el token real: es literalmente
   el bug de `env_file` que D1 cita.
5. Reemplazar el `chat_id` `CHANGE_ME` de `infra/alertmanager/alertmanager.yml`
   (los dos receivers, `noc` y `noc-urgente`) por el chat_id real -- ver el
   procedimiento completo en `infra/alertmanager/receivers.telegram.yml.example`.
6. `docker compose -f infra/docker-compose.yml up -d alertmanager` --
   Compose falla al arrancar si `infra/secrets/telegram_bot_token` no
   existe (el `secrets:` de `infra/docker-compose.yml` lo exige), que es la
   señal correcta: "falta un paso de instalación", no un contenedor que
   arranca con Telegram roto en silencio.

## Rotación

Reemplazar el contenido de `infra/secrets/telegram_bot_token` (mismos
permisos, mismo formato de una línea sin comillas) y `docker compose
restart alertmanager`. No hace falta tocar `alertmanager.yml`: el `chat_id`
no cambia con una rotación de token, solo si el operador cambia de
grupo/canal.

## Verificación

`docker compose exec alertmanager amtool check-config /etc/alertmanager/secisp/alertmanager.yml`
valida la sintaxis, pero **no** prueba que el token/chat_id sean correctos
-- eso solo se ve disparando una alerta real o de prueba
(`amtool alert add ...` contra la API local, 127.0.0.1:9093) y confirmando
que el mensaje llega al chat de Telegram.
