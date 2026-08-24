# Perfil reducido para el escenario chico (host de 16 GB)

**Task** T-182 (E12a-T09) · **Specs** E12 §4.2.2 · E00b D-40 · E00 §9 P12-18 · **Check**
`internal/ops/doctor/pre_memory.go` (`secisp doctor --pre`)

## Por qué existe este documento

E00b D-40 suma, por primera vez, los tres presupuestos de memoria que antes nadie sumaba:
el panel de Grafana, el motor de detección y los merges en background de ClickHouse. La
regla es

```
(a) panel + (b) motor + (c) merges  ≤  0,85 × max_server_memory_usage
```

**Con los defaults del escenario mediano, el escenario chico (host de 16 GB) no cierra.**
16 GB de host dan `max_server_memory_usage` ≈ 9,6 GiB (60 % de la RAM, E12 §4.2.2), pero
los tres presupuestos por default piden 20 GiB — panel 6 GiB + motor 6 GiB + merges 8 GiB.
`secisp doctor --pre` NO falla al arrancar con esos defaults: ClickHouse acepta los tres
settings sin chistar. Falla la primera vez que un panel y un tick de detección coinciden
bajo merges activos, con `MEMORY_LIMIT_EXCEEDED` en la query de detección — exactamente el
incidente que E12 §4.2.2 describe y que este documento existe para evitar.

**Este despliegue (E05 Q3, `F = 40.000`) NO necesita este perfil.** Con `F = 40.000` la
respuesta cae en el escenario mediano, donde la suma cierra con **8,8 GiB de margen** (28,8
GiB de techo contra 20 GiB pedidos). El documento queda listo para el día en que este mismo
código se despliegue en un ISP más chico (E00 §9 P12-18: "sigue viva como pregunta de
producto — el sistema tiene que poder usarlo otro ISP"), no porque haga falta hoy.

## Los cinco valores

Bajan cada uno de los tres sumandos de la fórmula. **Ninguno se toca en este despliegue**;
son la referencia para cuando corresponda.

| # | Valor | Default (mediano) | Reducido (chico) | Dónde se fija | Sumando |
|---|---|---|---|---|---|
| 1 | `max_memory_usage_for_user` del perfil `secisp_panel` | 6 GiB (`6442450944`) | **2 GiB** (`2147483648`) | `ALTER SETTINGS PROFILE secisp_panel` (o editar `deploy/clickhouse/94b_profile_panel.sql` antes de instalar) | (a) panel |
| 2 | `max_concurrent_queries_for_user` del perfil `secisp_panel` | 6 | **3** | mismo `ALTER SETTINGS PROFILE` que el punto 1 | — (no es memoria; limita cuántas queries de panel corren a la vez, referenciado junto al resto porque el bloque de §4.2.2 lo agrupa acá) |
| 3 | `SEC_DETECT_MAX_MEMORY_BYTES` | 2 GiB (`2147483648`) | **1 GiB** (`1073741824`) | `config.yaml` (`detect: max_memory_bytes:`) o variable de entorno | (b) motor |
| 4 | `SEC_DETECT_MAX_CONCURRENT_QUERIES` | 3 | **2** | `config.yaml` (`detect: max_concurrent_queries:`) o variable de entorno | (b) motor |
| 5 | `background_pool_size` del servidor ClickHouse | 16 (default de ClickHouse, sin cambiar) | **6** | `config.xml` / `config.d/*.xml` de ClickHouse (`changeable_without_restart = IncreaseOnly`: bajarlo pide reiniciar el server) | (c) merges |

Con estos cinco valores, la suma de la fórmula de D-40 da:

```
(a) 2 GiB + (b) 1 GiB × 2 + (c) 6 × 0,5 GiB  =  2 + 2 + 3  =  7 GiB
0,85 × 9,6 GiB (techo del escenario chico)   =  8,16 GiB
7 GiB ≤ 8,16 GiB → PASS
```

(0,5 GiB es el pico observado por merge de `agg_src_1m`, E12 §4.2.2 — una constante de
observación, no una fórmula.)

## Nota sobre el nombre de la variable 3+4 en la spec

La tabla de E12 §4.2.2 llama a la variable del punto 4 `SEC_DETECT_CONCURRENCY`. Esa
variable **no existe** con ese nombre en el catálogo real de 34 `SEC_DETECT_*` de E05 §5.9
(`internal/config/detect.go`, T-181): el nombre real es `SEC_DETECT_MAX_CONCURRENT_QUERIES`
— "semáforo de ejecución" de queries de detección concurrentes, default 3 (E05 §4.3.2/§4.7).
Los defaults coinciden dígito a dígito con la tabla de §4.2.2 (2 GiB × 3 = 6 GiB), lo que
confirma que es la misma variable con un nombre distinto en la tabla ilustrativa. Este
documento usa el nombre real, no el de la tabla.

## Cómo se verifica

`secisp doctor --pre` (el check "memoria: presupuesto de ClickHouse", `pre_memory.go`) lee
los valores efectivos de (1) y (3)+(4) de ClickHouse/config y da `FAIL` con los defaults del
escenario mediano sobre un host de 16 GB, `PASS` con los cinco valores de este documento —
son, literalmente, los dos casos de prueba de `internal/ops/doctor/pre_memory_test.go`
(`TestEvalMemoryBudget_MedianoDefaultsOnSixteenGBHostFails` /
`TestEvalMemoryBudget_EscenarioChicoPasses`).
