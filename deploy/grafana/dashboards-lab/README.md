# dashboards-lab — no se provisionan

Dashboards que dependen de infraestructura que **no existe en un despliegue
de producción**. `deploy/install.sh` solo copia `deploy/grafana/dashboards/`
(línea 234), así que nada de acá llega a Grafana.

## calidad-de-deteccion.json

Consulta cuatro métricas de Prometheus — `sec_evalset_recall`,
`sec_evalset_precision`, `sec_evalset_mttd_seconds`, `sec_evalset_would_be_fp`
— que **ningún daemon emite**. Las empuja `secisp evalset check` a un
Pushgateway (`internal/evalset/push.go`: "nunca scrapeadas directamente,
porque `secisp evalset check` es un proceso de CI que vive los segundos que
tarda una corrida"). E12 §5.8 lo dice de frente: evalset es "solo en lab y CI".

Para volver a activarlo hacen falta las cuatro cosas, no una:

1. Un Pushgateway. No hay ninguno en `infra/docker-compose.yml`.
2. Su job en `infra/prometheus/prometheus.yml`, **con `honor_labels: true`** —
   sin eso Prometheus pisa las etiquetas `detector`/`set` y los paneles
   quedan igual de vacíos.
3. `SEC_EVALSET_PUSHGATEWAY_URL` apuntando ahí (`ops.env`; vacía = no empuja).
4. Correr `secisp evalset run` + `check`. Los tres sets con `baseline.json`
   son `smoke`, `f1-mixto` y `adversario`.

Se movió acá el 2026-08-27 tras verificar que en la instalación real no
existía ninguno de los cuatro eslabones y el dashboard aparecía vacío en el
menú.
