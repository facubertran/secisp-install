-- 70_v_panel.sql [E10]
--
-- T-081 (E10-T03) -- E10 §4.2.2, §4.2.3, §5.1, D10 · E00b D-34, D-35 ·
-- E00c C-5, C-6.
--
-- Las dos vistas vertebrales del panel: isp.v_attack_events (un evento por
-- fila, enriquecido) y isp.v_attack_victims (una fila por (evento, víctima),
-- expandiendo top_dsts/top_dst_packets). El resto de §4.2 (v_attackers_now,
-- v_attack_pairs_1m, v_ops_blind, v_reputation_self, v_net_prefixes,
-- v_customer_ips, v_ops_panel_cost) se AGREGA a este mismo archivo en tasks
-- posteriores (T-082, T-083) -- por la regla de propiedad de archivos
-- (../../docs/plan/secuencia-de-desarrollo.md §7 bis), 70_v_panel.sql tiene
-- una sola épica dueña (E10) repartida en varias tasks, no varios archivos.
--
-- H-1 (E00f), verificado a mano antes de escribir esto: todo objeto isp.*
-- que estas vistas referencian vive en un archivo de número MENOR --
-- isp.v_det_events (40_det.sql), isp.dict_asn_meta / isp.dict_detector_family
-- (08_dict.sql), isp.dict_asn (08_dict.sql), isp_svc_str / net_label
-- (69b_udf_render.sql), net_scope / net_ignored_src (09_udf_net.sql),
-- isp_ip_str (00_database.sql). Si alguno faltara, el CREATE VIEW abortaría
-- y se llevaría puesto TODO 70_ en adelante, incluido 95_roles_grants.sql.
--
-- REGLA DEL tuple() (D-35, corregida por C-5), sin excepciones en este
-- archivo:
--   - isp.dict_asn      -- IP_TRIE (prefijo): tuple(victim_ip).
--   - isp.dict_detector_family -- COMPLEX_KEY_HASHED, PRIMARY KEY
--     detector_id String (C-6, gana E05 §5.4): tuple(e.detector_id).
--   - isp.dict_asn_meta -- HASHED con clave SIMPLE asn: SIN tuple(),
--     toUInt64(asn) a secas.
-- Mezclarlos rompe la vista en tiempo de CREATE (TYPE_MISMATCH/BAD_ARGUMENTS).
--
-- D-34: la UDF de render de IP es isp_ip_str -- NUNCA ip_str( ni isp.ip_str(.
--
-- El FINAL vive ADENTRO de isp.v_det_events (40_det.sql: "FROM
-- isp.det_events FINAL"). Estas dos vistas leen v_det_events, no det_events
-- directo, así que no lo repiten -- repetirlo acá sería un FINAL sobre un
-- FINAL, redundante y sin sentido semántico distinto.
--
-- Con isp.dim_asn_meta vacío o sin la fila del dst_asn (fase 1, semilla solo
-- CDN/cloud curados a mano en 06_dim_asn_meta.sql), dictGetOrDefault cae al
-- default declarado ('' / toUInt8(0)) y la vista NO falla (criterio E10-05).
--
-- D10: identity NO es "IP sin identificar". Tras P6 (sin CGNAT, exportación
-- pre-NAT), 'ip_only' solo puede salir de un prefijo declarado 'customer'
-- SIN customer_id (E04 V04) o removido después de la ingesta -- una IP que
-- no matchea ningún prefijo resuelve a scope='external' (DEFAULT, no 0) y da
-- flow_dir='transit', que ningún detector mira: nunca llega a det_events. Es
-- una alarma de inventario, no un dato faltante del panel.
--
-- Verificado mentalmente contra el contrato de columnas de §5.1 con un
-- SELECT ... LIMIT 0 antes de dar cada vista por buena: ningún alias
-- sombrea una columna real, y el contrato real de v_attack_events enumera
-- 57 columnas (no 56 -- incluye detector_family, que la lista y el cuerpo
-- SQL de E10 §4.2.2 sí traen; el "56" del texto de la task es un desvío de
-- redacción frente al contrato de §5.1, que es lo que manda por §3 del plan
-- de secuencia).

-- ═══════════════════════════════════════════════════════════════════════════
-- isp.v_attack_events -- un evento por fila, con todo lo que hace falta para
-- pintar cualquier panel de ataque sin JOIN en el panel (E10 §4.2.2).
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_attack_events
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT
    e.event_id                                        AS event_id,
    e.case_id                                         AS case_id,
    e.window_start                                    AS window_start,
    e.window_end                                      AS window_end,
    e.detected_at                                     AS detected_at,
    e.window_seconds                                  AS window_seconds,

    -- ── quién ataca ────────────────────────────────────────────────────
    e.src_ip                                          AS src_ip,
    e.src_ip_str                                      AS src_ip_str,
    e.src_ip_version                                  AS src_ip_version,
    e.customer_id                                     AS customer_id,
    e.src_prefix                                      AS src_prefix,
    e.src_asn                                         AS src_asn,
    -- D10: customer_id (si != '') > label del prefijo > la IP en texto.
    multiIf(e.customer_id != '',        e.customer_id,
            net_label(e.src_ip) != '',  net_label(e.src_ip),
            e.src_ip_str)                             AS attacker_label,
    -- D10: subscriber (normal) / shared_infra (prefijo 'infra') / ip_only
    -- (alarma de inventario -- prefijo 'customer' sin customer_id).
    multiIf(e.customer_id != '',       'subscriber',
            net_scope(e.src_ip) = 2,   'shared_infra',
            'ip_only')                                AS identity,
    net_ignored_src(e.src_ip)                         AS src_ignored,

    -- ── a quién ────────────────────────────────────────────────────────
    e.dst_kind                                        AS dst_kind,
    e.dst_ip                                          AS dst_ip,
    e.dst_ip_str                                      AS dst_ip_str,
    e.dst_port                                        AS dst_port,
    e.proto                                           AS proto,
    isp_svc_str(e.proto, e.dst_port)                  AS service,
    e.dst_asn                                         AS dst_asn,
    -- dict_asn_meta es HASHED con clave SIMPLE asn: SIN tuple(). Vacío o sin
    -- la fila -> '' (criterio E10-05, fase 1).
    dictGetOrDefault('isp.dict_asn_meta', 'as_name',
                     toUInt64(e.dst_asn), '')         AS dst_as_name,
    dictGetOrDefault('isp.dict_asn_meta', 'is_cdn',
                     toUInt64(e.dst_asn), toUInt8(0)) AS dst_is_cdn,
    e.dst_cc                                          AS dst_cc,
    e.top_dsts                                        AS top_dsts,
    e.top_dsts_str                                    AS top_dsts_str,
    e.top_dst_packets                                 AS top_dst_packets,

    -- ── cuánto ─────────────────────────────────────────────────────────
    e.packets, e.bytes, e.flows, e.pps, e.bps,
    e.uniq_dst_ips, e.uniq_dst_ports, e.uniq_dst_asns, e.syn_packets,
    e.sampling_max, e.cardinality_exact,

    -- ── por qué ────────────────────────────────────────────────────────
    e.detector_id, e.detector_version, e.attack_class, e.attack_subtype,
    e.method, e.score, e.severity, e.confidence,
    e.observed_value, e.threshold_value, e.baseline_value,
    e.deviation_sigma, e.ratio,
    e.suppressed, e.suppress_reason,
    e.evidence, e.engine_instance,
    -- dict_detector_family es COMPLEX_KEY_HASHED, PRIMARY KEY detector_id
    -- String (C-6, gana E05 §5.4): la clave va en tuple().
    dictGetOrDefault('isp.dict_detector_family', 'family',
                     tuple(e.detector_id), 'unknown') AS detector_family
FROM isp.v_det_events AS e;

-- ═══════════════════════════════════════════════════════════════════════════
-- isp.v_attack_victims -- una fila por (evento, víctima). Expande
-- top_dsts/top_dst_packets, que E00 §4.3.1 garantiza pareados y de largo
-- <= 20 (E10 §4.2.3). Es la fuente canónica de "los destinos" en cualquier
-- rango temporal.
--
-- length(top_dsts) > 0 filtra los eventos sin destinos (dst_kind='none',
-- p.ej. un detector que agrega por origen sin víctima identificada): un
-- evento con top_dsts vacío no produce ninguna fila acá.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_attack_victims
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT
    window_start, window_end, detected_at,
    case_id, event_id, detector_id, attack_class, attack_subtype,
    src_ip, src_ip_str, attacker_label, customer_id, identity,
    proto, dst_port, service,
    victim_ip,
    isp_ip_str(victim_ip)                              AS victim_ip_str,
    victim_packets,
    -- dict_asn es IP_TRIE: la clave va en tuple() (D-35 / C-5).
    dictGetOrDefault('isp.dict_asn', 'asn',     tuple(victim_ip), toUInt32(0))  AS victim_asn,
    dictGetOrDefault('isp.dict_asn', 'as_name', tuple(victim_ip), '')           AS victim_as_name,
    dictGetOrDefault('isp.dict_asn', 'cc',      tuple(victim_ip), '')           AS victim_cc,
    -- dict_asn_meta es HASHED con clave simple asn: va SIN tupla.
    dictGetOrDefault('isp.dict_asn_meta', 'is_cdn',
                     toUInt64(dictGetOrDefault('isp.dict_asn', 'asn',
                              tuple(victim_ip), toUInt32(0))), toUInt8(0))      AS victim_is_cdn,
    net_scope(victim_ip)                               AS victim_scope,
    score, severity, confidence, suppressed, sampling_max
FROM
(
    SELECT
        *,
        arrayJoin(arrayZip(top_dsts, top_dst_packets)) AS z,
        z.1                                            AS victim_ip,
        z.2                                            AS victim_packets
    FROM isp.v_attack_events
    WHERE length(top_dsts) > 0
);

-- ═══════════════════════════════════════════════════════════════════════════
-- T-082 (E10-T04) -- E10 §4.2.4, §4.2.5, §5.1, D5, D4 · E00b D-10 · E00c C-2.
--
-- El "ahora" del panel: isp.v_attackers_now (casos vivos + tasa instantánea)
-- e isp.v_attack_pairs_1m (detalle vivo origen->destino). Igual que arriba,
-- ambas se AGREGAN a este mismo archivo -- 70_v_panel.sql sigue teniendo una
-- sola épica dueña (E10), repartida en varias tasks (§7 bis).
--
-- D5, sin excepciones: v_attackers_now lleva "now() - INTERVAL 3 MINUTE"
-- ADENTRO. El time picker de Grafana NO la afecta -- es DELIBERADO. Mezclar
-- ventana fija y time picker es justo lo que rompió el prototipo: un
-- operador que se dejó el rango en "7 días" vería "atacantes activos: 340" y
-- no sabría que 339 terminaron el jueves. `isp.v_attack_events`,
-- `isp.v_attack_victims` y `isp.v_attack_pairs_1m` van sin ningún predicado
-- temporal adentro -- el panel aplica $__timeFilter(window_start).
--
-- D4: el JOIN de v_attackers_now es chico contra chico (casos activos: a lo
-- sumo cientos) contra chico (3 min de agg_src_1m) -- por eso está permitido
-- dentro de una vista. El lado derecho va ENVUELTO EN SUBCONSULTA
-- (`SELECT * FROM isp.v_agg_src_1m WHERE window_start >= ...`) porque
-- isp.v_agg_src_1m YA tiene GROUP BY (21_agg_src_1m.sql); re-agregar
-- (max(pps), max(bps), max(uniq_dst_ips)) directamente sobre ella sin ese
-- envoltorio es ILLEGAL_AGGREGATION.
--
-- staleness_s = now() - last_event_at, y NO es "atacando ahora": un caso
-- queda 'open' hasta SEC_DETECT_CASE_IDLE_SECONDS (900 s) sin eventos, así
-- que "activo" != "atacando en este instante". El panel ordena por
-- staleness_s ascendente y colorea en rojo < 120 s.
--
-- GOTCHA DE TIPO, verificado con toTypeName() contra el ClickHouse 24.8 de
-- infra/docker-compose.yml -- no es un problema de diseño, es cómo
-- ClickHouse tipa la resta de DateTime:
--   SELECT toTypeName(now() - toDateTime(0))              -- Int32, NO Int64
-- El contrato de §5.1 fija `staleness_s Int64` y `duration_s Int64` (esta
-- última ya es Int32 nativa en isp.v_det_cases, 40_det.sql: mismo defecto,
-- columna ajena que no se toca por la regla de propiedad de §7 bis). El SQL
-- textual de E10 §4.2.4 escribe "now() - c.last_event_at" y "c.duration_s" a
-- secas -- eso compila pero da Int32, no Int64: el `DESCRIBE` del criterio de
-- aceptación fallaría en silencio contra un ClickHouse real. Se resuelve con
-- el mismo patrón que ya usa 50_mit.sql para expires_in_s
-- (`toInt64(expires_at) - toInt64(now())`): castear cada operando a Int64
-- ANTES de restar.
--
-- v_attack_pairs_1m hereda el GROUP BY de isp.v_agg_src_dst_svc_1m
-- (25_agg_src_dst_svc_1m.sql, ola 2): un SELECT sum(...)/GROUP BY directo
-- sobre ella es ILLEGAL_AGGREGATION por diseño (C5 del panel) -- los paneles
-- la envuelven en subconsulta. Deliberadamente NO se lee
-- isp.v_agg_src_dst_svc_1m_flat: esa variante (D-10/C-2) es de los
-- detectores y puede devolver la misma clave partida en varias filas cuando
-- hay partes sin fusionar (finalizeAggregation() fila a fila, sin merge) --
-- en una tabla de panel eso se ve plausible y es falso. El atacante se
-- resuelve con net_customer(p.src_ip) (09_udf_net.sql): a diferencia de
-- v_attack_events, esta vista no tiene columna customer_id resuelta -- D-11
-- no la agrega a agg_src_dst_svc_1m por costo (se paga en la tabla más
-- grande del esquema).
--
-- dictGet: dict_asn (IP_TRIE) va con tuple(); dict_asn_meta (HASHED, clave
-- simple asn) va SIN tuple() -- misma regla que 40_det.sql y el resto de
-- este archivo (D-35/C-5).
--
-- Contado columna por columna contra el contrato de §5.1 (y contra el cuerpo
-- SQL de §4.2.4, que trae exactamente las mismas): v_attackers_now tiene 28
-- columnas, no 29 -- mismo tipo de desvío de redacción que el "56" de
-- v_attack_events (nota de T-081, arriba), y gana el contrato (§3 del plan de
-- secuencia), no la aritmética del texto de la task.
-- ═══════════════════════════════════════════════════════════════════════════

-- isp.v_attackers_now -- casos vivos + su tasa instantánea (E10 §4.2.4).
CREATE OR REPLACE VIEW isp.v_attackers_now
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT
    c.case_id                     AS case_id,
    c.src_ip                      AS src_ip,
    c.src_ip_str                  AS src_ip_str,
    c.customer_id                 AS customer_id,
    -- D10: customer_id (si != '') > label del prefijo > la IP en texto.
    multiIf(c.customer_id != '',        c.customer_id,
            net_label(c.src_ip) != '',  net_label(c.src_ip),
            c.src_ip_str)         AS attacker_label,
    multiIf(c.customer_id != '',     'subscriber',
            net_scope(c.src_ip) = 2, 'shared_infra',
            'ip_only')            AS identity,
    c.attack_class                AS attack_class,
    c.state                       AS state,
    c.opened_at                   AS opened_at,
    c.last_event_at               AS last_event_at,
    -- Int64 explícito -- ver GOTCHA DE TIPO en el comentario de cabecera.
    toInt64(now()) - toInt64(c.last_event_at)     AS staleness_s,
    toInt64(c.duration_s)         AS duration_s,
    c.peak_score                  AS peak_score,
    c.peak_pps                    AS peak_pps,
    c.peak_bps                    AS peak_bps,
    c.peak_uniq_dst               AS peak_uniq_dst,
    c.victim_count                AS victim_count,
    c.victims_sample_str          AS victims_sample_str,
    c.detectors                   AS detectors,
    c.detector_count              AS detector_count,
    c.distinct_families           AS distinct_families,
    c.mitigation_count            AS mitigation_count,
    c.last_action                 AS last_action,
    c.event_count                 AS event_count,
    net_ignored_src(c.src_ip)     AS src_ignored,
    -- Tasa vigente, de los últimos 3 minutos de agregado por origen. Un caso
    -- activo sin tráfico reciente en agg_src_1m sale con 0/0/0, no
    -- desaparece del panel (LEFT JOIN + ifNull).
    ifNull(l.pps_now, 0.)         AS pps_now,
    ifNull(l.bps_now, 0.)         AS bps_now,
    ifNull(l.uniq_dst_now, 0)     AS uniq_dst_now
FROM
(
    SELECT * FROM isp.v_det_cases WHERE is_active
) AS c
LEFT JOIN
(
    -- Envuelto en subconsulta: isp.v_agg_src_1m YA tiene GROUP BY
    -- (21_agg_src_1m.sql) -- reagregar sin este envoltorio es
    -- ILLEGAL_AGGREGATION (D4).
    SELECT src_ip,
           max(pps)          AS pps_now,
           max(bps)          AS bps_now,
           max(uniq_dst_ips) AS uniq_dst_now
    FROM (SELECT * FROM isp.v_agg_src_1m
          WHERE window_start >= toStartOfMinute(now() - INTERVAL 3 MINUTE))
    GROUP BY src_ip
) AS l USING (src_ip);

-- isp.v_attack_pairs_1m -- detalle vivo origen->destino, pass-through
-- enriquecido de isp.v_agg_src_dst_svc_1m (TTL 6 h, E10 §4.2.5).
CREATE OR REPLACE VIEW isp.v_attack_pairs_1m
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT
    p.window_start, p.src_ip, p.src_ip_str,
    -- net_customer(p.src_ip), no una columna customer_id: v_agg_src_dst_svc_1m
    -- no la trae (D-11) -- a diferencia de v_attack_events, que ya la resuelve
    -- desde det_events.
    multiIf(net_customer(p.src_ip) != '', net_customer(p.src_ip),
            net_label(p.src_ip) != '',    net_label(p.src_ip),
            p.src_ip_str)                                  AS attacker_label,
    p.dst_ip, p.dst_ip_str, p.proto, p.dst_port,
    isp_svc_str(p.proto, p.dst_port)                        AS service,
    p.dst_asn,
    -- dict_asn: IP_TRIE -> tuple(). dict_asn_meta: HASHED, clave simple -> sin
    -- tuple() (D-35/C-5).
    dictGetOrDefault('isp.dict_asn', 'as_name', tuple(p.dst_ip), '')      AS dst_as_name,
    dictGetOrDefault('isp.dict_asn', 'cc',      tuple(p.dst_ip), '')      AS dst_cc,
    dictGetOrDefault('isp.dict_asn_meta', 'is_cdn',
                     toUInt64(p.dst_asn), toUInt8(0))                     AS dst_is_cdn,
    net_scope(p.dst_ip)                                     AS dst_scope,
    p.bytes, p.packets, p.flows, p.syn_only_packets,
    p.established_flows, p.flags_valid_flows,
    p.first_seen, p.last_seen, p.pps, p.bps, p.sampling_max
FROM isp.v_agg_src_dst_svc_1m AS p;

-- ═══════════════════════════════════════════════════════════════════════════
-- T-083 (E10-T05) -- E10 §4.2.6, §5.1, D8 · E00f H-1 · E10 §9.1 Q2.
--
-- Las cinco vistas de estado, salud y contexto: isp.v_ops_blind,
-- isp.v_reputation_self, isp.v_net_prefixes, isp.v_customer_ips e
-- isp.v_ops_panel_cost. Igual que arriba, se AGREGAN a este mismo archivo --
-- 70_v_panel.sql sigue teniendo una sola épica dueña (E10), repartida en
-- varias tasks (§7 bis).
--
-- H-1 (E00f), verificado leyendo los cuatro archivos antes de escribir esto,
-- no asumiéndolo:
--   - isp.v_ops_data_health   -- 39_v_ops_data_health.sql [E03]. Expone
--     `flags_flows_5m` con ese nombre EXACTO (línea "AS flags_flows_5m"),
--     así que v_ops_blind la usa sin ajustar nada.
--   - isp.v_exporter_status   -- 11_v_exporter_status.sql [E04].
--   - isp.v_det_runs          -- 43_v_det.sql [E05].
--   - isp.v_det_detectors     -- 43_v_det.sql [E05]. La agrega el fix de la
--     rama "detección atrasada": aporta `cadence_seconds` (el presupuesto de
--     atraso de cada detector) y `mode` (para excluir los que ni corren).
--     Mismo archivo que v_det_runs, así que no suma un archivo nuevo a H-1.
--   - isp.ops_reputation_self -- 39b_ops_reputation_self.sql [E04] (tabla,
--     no vista -- v_reputation_self la envuelve con FINAL).
-- Los cuatro números (39, 39b, 11, 43) son MENORES que 70: si alguno no
-- existiera a esta altura, el CREATE VIEW abortaría y se llevaría puesto
-- TODO 70_ en adelante, incluido 95_roles_grants.sql.
--
-- GOTCHA DE TIPO en v_ops_blind.detect_lag_s -- mismo defecto que
-- staleness_s/duration_s en la nota de cabecera de T-082 (arriba), verificado
-- con toTypeName() contra el ClickHouse 24.8 real: isp.v_det_runs.lag_s sale
-- de "now() - window_end" (43_v_det.sql), y window_end es DateTime('UTC') sin
-- milisegundos -- esa resta tipa Int32, NO Int64. El contrato de §5.1 fija
-- `detect_lag_s Int64`: se envuelve el `max(lag_s)` en `toInt64(...)` para que
-- el `DESCRIBE` del criterio de aceptación no falle en silencio. El resto de
-- columnas de v_ops_blind ya salen en el tipo correcto sin cast: `ingest_lag_s`
-- viene de `dateDiff('second', …)` (siempre Int64, no la resta de DateTime que
-- da el problema) y los `count()` son UInt64 de por sí.
--
-- `status_text` se referencia como alias dentro del `multiIf` de
-- `severity_num`: es legal en ClickHouse -- una expresión del SELECT puede
-- usar el alias de una expresión anterior del MISMO SELECT -- y no sombrea
-- ninguna columna real (no hay `status_text` en isp.v_ops_data_health).
-- Verificado mentalmente con un `SELECT … LIMIT 0` antes de dar la vista por
-- buena. No es el caso CYCLIC_ALIASES (C-13/G-4b) de 35_/37_: ahí el conflicto
-- es renombrar una columna de tiempo A SU PROPIO NOMBRE; acá son dos alias
-- DISTINTOS (`status_text` != `severity_num`), sin ciclo.
--
-- SQL SECURITY DEFINER (N2/Q2, ClickHouse >= 24.4, fijado en 24.8 -- Q17):
-- v_ops_panel_cost lee `system.query_log`, y secisp_ro/secisp_grafana NO van
-- a tener GRANT sobre `system.*` (E12 §5.7.2 lo fija así, para no exponerles
-- el texto completo de las queries -- que incluye IPs de clientes en los
-- WHERE del drill-down). Sin la vista corriendo con privilegios propios, el
-- panel de costo por panel (D8) no arranca para el usuario de Grafana.
--
-- DESVÍO DEL TEXTO LITERAL de E12 §5.7.2 -- justificado por H-1, que pesa más
-- que el texto de una épica (§3 del plan de secuencia): el ejemplo de E12 usa
-- `DEFINER = secisp_ops SQL SECURITY DEFINER`, pero `secisp_ops` es un USUARIO
-- que crea `95_roles_grants.sql` (E12, T-092) -- número MAYOR que 70. Un
-- `CREATE VIEW` que nombra ese usuario en `DEFINER = …` desde acá fallaría con
-- el usuario inexistente y se llevaría puesto TODO 70_ en adelante: exactamente
-- la misma clase de bug que H-1 corrige para objetos `isp.*`, aplicada a un
-- usuario del sistema. Se usa `SQL SECURITY DEFINER` SIN `DEFINER = …`
-- explícito: el default es `CURRENT_USER`, resuelto AL CREAR la vista (quien
-- corre `secisp schema apply`, con ACCESS MANAGEMENT completo) -- logra el
-- mismo efecto (la vista lee `system.query_log` con privilegios propios, no
-- del invocador) sin referenciar nada que todavía no existe. Si más adelante
-- se quiere atar el DEFINER a `secisp_ops` puntualmente, T-092 puede hacerlo
-- en `95_` con `ALTER TABLE isp.v_ops_panel_cost MODIFY SQL SECURITY DEFINER
-- DEFINER secisp_ops` una vez que ese usuario ya exista -- no hace falta para
-- que el panel funcione.
--
-- GAP CERRADO POR T-092 (era "GAP CONOCIDO" hasta acá): `isp.v_ops_data_health`
-- (39_) TAMBIÉN lee `system.parts`, y hasta T-092 se creaba SIN `SQL SECURITY
-- DEFINER` -- `secisp_ro`/`secisp_grafana` pegaban ACCESS_DENIED sobre
-- `system.parts` en cuanto consultaban `isp.v_ops_blind` (que lee
-- `v_ops_data_health`), sin un GRANT amplio sobre `system.*` -- que es justo lo
-- que E12 §5.7.2 decidió NO otorgar. T-092 le agregó la cláusula a
-- `39_v_ops_data_health.sql` (ver el comentario de cabecera de ese archivo) al
-- generalizar SQL SECURITY DEFINER a las 46 vistas otorgadas a secisp_ro, no
-- solo a las dos que tocan `system.*` literal.
CREATE OR REPLACE VIEW isp.v_ops_blind
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
WITH
-- FIX (bug de la rama "detección atrasada"): el atraso REAL del motor, por
-- detector, contra el presupuesto de CADA detector.
--
-- QUÉ ESTABA MAL. La versión anterior hacía
--   (SELECT max(lag_s) FROM isp.v_det_runs WHERE evaluated_at >= now() - INTERVAL 30 MINUTE)
-- y `lag_s` es `now() - window_end` recalculado en CADA consulta (43_v_det.sql).
-- Como isp.ops_detect_state guarda UNA FILA POR DETECTOR Y POR VENTANA
-- (ReplacingMergeTree ORDER BY (detector_id, window_start), 40_det.sql), la
-- ventana de 30 min SIEMPRE contiene filas escritas hace ~29 min, cuyo lag_s
-- hoy vale ~1800 s. O sea: `max(lag_s) > 300` era VERDADERO SIEMPRE en un
-- motor sano, a los ~5 min de arrancar. Y al revés: con el motor MUERTO hace
-- más de 30 min ninguna fila pasaba el filtro, `max()` sobre cero filas
-- devuelve 0 en ClickHouse (misma trampa que documenta
-- internal/detect/framework/state.go, que por eso acompaña su max con un
-- count()), `0 > 300` era falso y la vista publicaba 'OK'. La ficha se
-- encendía con todo bien y se apagaba con el motor caído. Reproducido y
-- corregido contra ClickHouse 24.8 real.
--
-- QUÉ MIDE AHORA. Por cada detector, `now() - max(window_end)` sobre las
-- corridas que CUENTAN COMO PROGRESO (`status IN ('ok','skipped')`): es
-- literalmente el watermark del motor (internal/detect/framework/state.go) y
-- el mismo criterio del check `detect_watermark` del watchdog
-- (internal/obs/checks/freshness.go). 'error'/'timeout'/'pending'/'degraded'
-- NO avanzan el watermark, así que contarlos pintaría de al-día a un detector
-- trabado.
--
-- POR QUÉ EL UMBRAL ES POR DETECTOR Y NO UN 300 FIJO. El pico de atraso SANO
-- de un detector es `EffectiveCadence + Grace + tick`, y las cadencias reales
-- van de 10 s (ddos.src_flood) a 3600 s (anomaly.new_service/service_wave),
-- pasando por 300 s (los siete smtp.* y scan.sweep_slow). Un 300 fijo deja
-- CINCO de los 28 detectores en falso positivo permanente. `cadence_seconds`
-- de isp.dim_detectors ya es la cadencia EFECTIVA (catalog.go la escribe con
-- `spec.Window.EffectiveCadence()`, que resuelve Cadence=0 a Length), así que
-- `cadence_seconds + 300` es "más de cinco minutos por detrás de su propio
-- ciclo" y cubre el Grace más grande del repo (90 s, anomaly.level_shift).
--
-- POR QUÉ SE EXCLUYE mode='off'. El motor saltea esos detectores antes de
-- planificar ("el detector ni corre", internal/detect/framework/engine.go), o
-- sea que su watermark queda congelado para siempre: sin este filtro, un
-- detector deshabilitado a propósito dispararía la alerta eternamente. El
-- INNER JOIN además excluye solo a los detectores sembrados en dim_detectors
-- que nunca corrieron en este despliegue, y a la fila sintética
-- '__replay_cursor__' (que se escribe con status='ok' y window_end congelado
-- al terminar el replay del WAL: sin excluirla sería el máximo eterno; misma
-- exclusión que internal/obs/checks/freshness.go).
--
-- POR QUÉ EL JOIN VA ADENTRO DE UN `WITH` ESCALAR Y NO EN EL FROM. Verificado
-- contra ClickHouse 24.8 real: con un JOIN en el nivel superior de la vista,
-- `SELECT *` falla con "Code: 80 ... returned Nullable column having not
-- Nullable type in structure ... if query from view has JOIN, it may be cause
-- by different values of 'join_use_nulls'", y las que rompen son las OTRAS
-- columnas de subquery escalar (exporters_down/exporters_total/
-- detect_failures_30m), que este fix ni toca. Anidado dentro del `WITH` el
-- nivel superior sigue teniendo un solo FROM y la vista responde bien.
--
-- LA VENTANA DE 1 DÍA acota el GROUP BY (window_start es la clave de
-- PARTITION BY, así que poda particiones). Un detector atrasado MÁS de un día
-- desaparece de este conjunto y cae en la rama 'CIEGO: sin detección', que es
-- la lectura correcta a esa altura.
(
    SELECT (max(atraso_s), countIf(atraso_s > d.cadence_seconds + 300), count())
    FROM (
        SELECT detector_id,
               dateDiff('second', max(window_end), now()) AS atraso_s
        FROM isp.v_det_runs
        WHERE status IN ('ok', 'skipped')
          AND detector_id != '__replay_cursor__'
          AND window_start >= now() - INTERVAL 1 DAY
        GROUP BY detector_id
    ) AS w
    INNER JOIN (
        -- CAST(... AS String) despega el LowCardinality de la clave y del
        -- predicado, por la misma razón que 43_v_det.sql lo hace en
        -- is_actionable (ClickHouse rechaza LowCardinality(UInt8) de salida).
        SELECT CAST(detector_id AS String) AS detector_id, cadence_seconds
        FROM isp.v_det_detectors
        WHERE CAST(mode AS String) != 'off'
    ) AS d USING (detector_id)
) AS det,
(
    SELECT count() FROM isp.v_det_detectors WHERE CAST(mode AS String) != 'off'
) AS detectores_habilitados
SELECT
    h.ingest_lag_seconds                                    AS ingest_lag_s,
    h.unknown_scope_5m                                      AS unknown_scope_5m,
    h.transit_flows_5m                                      AS transit_flows_5m,
    (SELECT count() FROM isp.v_exporter_status
       WHERE status != 'ok')                                AS exporters_down,
    (SELECT count() FROM isp.v_exporter_status)              AS exporters_total,
    -- toInt64(): el contrato de §5.1 fija `detect_lag_s Int64`. dateDiff ya
    -- devuelve Int64 (no la resta de DateTime, que da Int32 -- ver el GOTCHA
    -- DE TIPO de la cabecera), pero el cast queda explícito para que el
    -- DESCRIBE del criterio de aceptación no dependa de eso.
    toInt64(det.1)                                           AS detect_lag_s,
    (SELECT count() FROM isp.v_det_runs
       WHERE evaluated_at >= now() - INTERVAL 30 MINUTE
         AND status IN ('error','timeout','breaker_open'))  AS detect_failures_30m,
    multiIf(
        h.ingest_lag_seconds > 300,                    'CIEGO: sin flujos hace >5 min',
        h.ingest_lag_seconds > 120,                    'DEGRADADO: ingesta atrasada',
        (SELECT count() FROM isp.v_exporter_status
           WHERE status != 'ok') > 0,                  'DEGRADADO: exportador mudo',
        h.unknown_scope_5m > 0
          AND h.unknown_scope_5m > h.flags_flows_5m,   'CIEGO: prefijos de cliente sin cargar',
        -- Hay detectores habilitados pero NINGUNO tiene una sola ventana
        -- evaluada en el último día: motor detenido hace rato, recién
        -- instalado, o atrasado más allá de la ventana de arriba. Es CIEGO,
        -- no DEGRADADO: no se está detectando nada. Va ANTES de las dos ramas
        -- de detección porque con cero corridas las dos darían 0 y la vista
        -- caería en 'OK' -- el falso negativo que este fix cierra.
        detectores_habilitados > 0 AND det.3 = 0,      'CIEGO: sin detección',
        (SELECT count() FROM isp.v_det_runs
           WHERE evaluated_at >= now() - INTERVAL 30 MINUTE
             AND status IN ('error','timeout','breaker_open')) > 0,
                                                        'DEGRADADO: detector fallando',
        det.2 > 0,                                      'DEGRADADO: detección atrasada',
        'OK')                                                AS status_text,
    multiIf(position(status_text, 'CIEGO') > 0, 2,
            position(status_text, 'DEGRADADO') > 0, 1,
            0)                                               AS severity_num
FROM isp.v_ops_data_health AS h;

-- isp.v_reputation_self -- reputación propia: el ÚNICO indicador de resultado
-- del sistema (E04 §4.9.3). FINAL sobre ops_reputation_self (39b_,
-- ReplacingMergeTree) -- ver nota de cabecera del archivo sobre por qué las
-- lecturas de tablas base van con FINAL.
CREATE OR REPLACE VIEW isp.v_reputation_self
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT
    checked_at, ip, isp_ip_str(ip) AS ip_str, prefix, list_id, listed,
    detail, first_seen, customer_id,
    dateDiff('day', first_seen, now()) AS days_listed
FROM isp.ops_reputation_self FINAL;

-- isp.v_net_prefixes -- prefijos, para la variable $customer_net y el
-- contexto del drill-down. FINAL + is_enabled = 1 (borrado lógico, D-N2 de
-- 05_dim_net_prefixes.sql: is_enabled NO participa de la ORDER BY, así que el
-- filtro tiene que ir en cada lectura).
CREATE OR REPLACE VIEW isp.v_net_prefixes
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT prefix, scope, customer_id, ignore_src, ignore_dst, label, owner,
       expires_at, is_enabled, updated_at, updated_by
FROM isp.dim_net_prefixes FINAL
WHERE is_enabled = 1;

-- isp.v_customer_ips -- histórico de asignación de IP a abonado (forense del
-- drill-down). FINAL sobre dim_customer_ips (09_, ReplacingMergeTree).
-- is_open = 1 cuando la sesión está abierta: '2106-02-07 06:28:15' (UTC,
-- 4294967295 = máximo de DateTime de 32 bits) es el default de `ended_at`
-- mientras no llega el Stop de RADIUS/lease de DHCP (09_dim_customer_ips.sql).
CREATE OR REPLACE VIEW isp.v_customer_ips
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT ip, isp_ip_str(ip) AS ip_str, customer_id, started_at, ended_at,
       source, nas_id, username,
       if(ended_at >= toDateTime(4294967295), 1, 0) AS is_open
FROM isp.dim_customer_ips FINAL;

-- isp.v_ops_panel_cost -- costo por panel (D8). La lee el dashboard de
-- pipeline y el bench de CI: `log_comment` es el que cada panel fija con
-- `SETTINGS log_comment = 'secisp:<dashboard>:<panel_id>'` (D8), y el
-- `LIKE 'secisp:%'` de abajo excluye cualquier query manual o de otro sistema
-- que comparta el mismo `system.query_log`.
--
-- SQL SECURITY DEFINER sin DEFINER explícito -- ver GOTCHA de SQL SECURITY
-- DEFINER en el comentario de cabecera de este bloque: el default
-- (CURRENT_USER, resuelto al CREATE) evita referenciar `secisp_ops`, que
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
CREATE OR REPLACE VIEW isp.v_ops_panel_cost
SQL SECURITY DEFINER
AS
SELECT
    log_comment                                          AS panel,
    count()                                              AS runs,
    round(quantile(0.95)(query_duration_ms))             AS p95_ms,
    max(query_duration_ms)                               AS max_ms,
    round(quantile(0.95)(read_rows))                     AS p95_rows,
    max(read_rows)                                       AS max_rows,
    max(memory_usage)                                    AS max_memory_bytes,
    countIf(type = 'ExceptionWhileProcessing')           AS errors,
    round(countIf(ProfileEvents['QueryCacheHits'] > 0) / count(), 3) AS cache_hit_ratio
FROM system.query_log
WHERE event_time >= now() - INTERVAL 24 HOUR
  AND type IN ('QueryFinish', 'ExceptionWhileProcessing')
  AND log_comment LIKE 'secisp:%'
GROUP BY panel;
