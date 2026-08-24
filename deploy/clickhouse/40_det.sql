-- 40_det.sql [E05]
--
-- T-073 (E05-T05) -- E05 §5.1, §5.2, §5.4 · E00 §4.3.1, §4.3.6 · E00b D-13,
-- D-28, D-36 · E00c C-6, C-7 · E05 §9 Q10.
--
-- Bloque nuclear del motor de detección: las dos tablas de evento/caso cuyo
-- DDL es LITERAL de E00 (§4.3.1, §4.3.6 -- "no se modifica") y la tabla de
-- watermark/bitácora propia de E05 (§5.2). Nombra explícitamente
-- ops_detect_state porque v_det_runs (43_v_det.sql) la lee con FINAL.
--
-- C-7 / D-25: ratio_adjust es columna REAL de det_events (Float64 DEFAULT
-- 1.0), no un campo derivado de evidence. El motor la escribe SIEMPRE
-- explícita en el INSERT (§5.1.1) -- el DEFAULT es solo la red de seguridad
-- de un ALTER futuro, nunca la fuente de "el detector no ajustó".
--
-- Q10: detector_families Array(LowCardinality(String)) se PERSISTE en
-- det_cases (enmienda a E00 §4.3.6 ya aplicada); no se deriva con un dictGet
-- contra el dim_detectors del presente -- si alguien reclasifica la family de
-- un detector, la auditoría de por qué se autorizó una mitigación tiene que
-- seguir siendo reconstruible con los datos de cuando el caso se abrió.
--
-- D-28: NO existe isp.dim_detect_exceptions. La única tabla de supresión de
-- todo el sistema es isp.det_suppress_rules (41_det_suppress.sql).
--
-- D-36: isp.ops_audit es de E12 §5.4 (DDL canónico ahí). E05 la ESCRIBE
-- (cambios de modo, params_drift, dismiss de casos) pero no la declara en
-- ningún archivo de esta épica -- vive en 90_ops_audit.sql. Tampoco se
-- transcribe acá ningún GRANT: eso es 95_roles_grants.sql, de E12.
--
-- Por la regla de propiedad de archivos (../../docs/plan/secuencia-de-
-- desarrollo.md §7 bis, nota final): T-074 (E05-T06) pierde este archivo como
-- entregable de escritura y le entrega a esta task el texto canónico de
-- v_det_events/v_det_cases -- las dos vistas que E05 §5.4 declara junto a
-- det_events/det_cases, con sus trampas D-34 (isp_ip_str, nunca ip_str( ni
-- isp.ip_str() y C-6/D-35 (dict_detector_family es COMPLEX_KEY_HASHED con
-- clave String: todo dictGet sobre él lleva tuple()). Las otras cuatro
-- vistas (v_det_case_events, v_det_runs, v_det_suppressed_1h,
-- v_det_detectors) y el diccionario dict_detector_family NO van acá: viven en
-- 43_v_det.sql y en 08_dict.sql respectivamente (T-074, T-066). Este archivo
-- va ANTES de esos dos porque 08 < 40 < 43 por orden lexicográfico -- pero
-- dict_detector_family carga diferido (dictionaries_lazy_load=1), así que su
-- SOURCE (v_det_detectors, creada en 43_) no tiene que existir todavía
-- cuando 08_dict.sql corre, y v_det_cases (creada acá, en 40_) puede llamar
-- dictGetOrDefault('isp.dict_detector_family', ...) porque el diccionario
-- YA existe como objeto para cuando el archivo 40 corre (08 < 40).

-- ═══════════════════════════════════════════════════════════════════════════
-- isp.det_events -- la observación (E00 §4.3.1, DDL LITERAL, no se modifica)
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS isp.det_events
(
    -- ══ Identidad ═══════════════════════════════════════════════════════════
    -- DETERMINÍSTICO: UUIDv5 sobre la cadena de fingerprint (E00 §4.3.2).
    -- El mismo detector, sobre la misma entidad, en la misma ventana, produce
    -- SIEMPRE el mismo event_id. Es a la vez referencia externa y clave de dedup.
    event_id         UUID,
    -- Correlación con det_cases. Nil UUID mientras el motor no lo asigne.
    case_id          UUID,

    -- ══ Tiempo ══════════════════════════════════════════════════════════════
    window_start     DateTime('UTC'),
    window_end       DateTime('UTC'),
    detected_at      DateTime64(3, 'UTC'),   -- cuándo corrió el detector

    -- ══ Qué detectó ═════════════════════════════════════════════════════════
    -- Namespace punteado, estable. Cambiar el umbral o la fórmula ⇒ subir
    -- detector_version. Cambiar QUÉ se detecta ⇒ detector_id NUEVO.
    detector_id      LowCardinality(String),   -- 'scan.horizontal', 'smtp.fanout', ...
    detector_version UInt16,
    -- Enum CERRADO, propiedad de E00. Agregar un valor = enmienda a este doc.
    attack_class     Enum8('scan'=1, 'smtp_spam'=2, 'ddos_out'=3, 'reflection'=4,
                           'amplification'=5, 'anomaly'=6, 'policy'=7, 'other'=99),
    -- Texto libre de baja cardinalidad, propiedad del detector.
    -- 'horizontal', 'vertical', 'syn_unanswered', 'udp_flood', 'carpet_bombing',
    -- 'dns_reflector', 'ntp_monlist', 'ssdp', 'small_session', 'stalled', ...
    attack_subtype   LowCardinality(String),

    -- ══ Quién ataca (SIEMPRE el lado interno) ═══════════════════════════════
    src_ip           IPv6,
    src_ip_version   UInt8,
    customer_id      LowCardinality(String),
    src_prefix       String,        -- CIDR del bloque de cliente que matcheó, ej '203.0.113.0/29'
    src_asn          UInt32,

    -- ══ A quién ataca ═══════════════════════════════════════════════════════
    -- none   = el detector agrega por origen; no hay una víctima única
    -- single = una víctima identificada (dst_ip/proto/dst_port válidos)
    -- many   = muchas víctimas; ver top_dsts / uniq_dst_ips
    dst_kind         Enum8('none'=0, 'single'=1, 'many'=2),
    dst_ip           IPv6,          -- válido solo si dst_kind='single'
    dst_port         UInt16,        -- 0 si no aplica
    proto            UInt8,         -- 0 si no aplica
    dst_asn          UInt32,
    dst_cc           LowCardinality(String),
    -- Top-N destinos por paquetes (N ≤ 20). ARRAYS PAREADOS, mismo largo.
    -- Es lo que hace que el panel de E10 y la lista de víctimas de E11 no
    -- tengan que volver a consultar flows_raw.
    top_dsts         Array(IPv6),
    top_dst_packets  Array(UInt64),

    -- ══ Evidencia numérica (común a TODOS los detectores) ═══════════════════
    packets          UInt64,
    bytes            UInt64,
    flows            UInt64,
    pps              Float64,
    bps              Float64,
    uniq_dst_ips     UInt64,
    uniq_dst_ports   UInt64,
    uniq_dst_asns    UInt32,
    syn_packets      UInt64,        -- paquetes en flujos con SYN sin ACK
    -- Factor de sampling máximo de las filas que componen la evidencia.
    sampling_max     UInt32,
    -- 1 = las cardinalidades son exactas (uniqExact); 0 = aproximadas (HLL).
    cardinality_exact UInt8,

    -- ══ Scoring ═════════════════════════════════════════════════════════════
    -- threshold = umbral estático; baseline = desvío respecto del perfil (E09);
    -- hybrid = ambos coincidieron; manual = lo cargó un operador.
    method           Enum8('threshold'=1, 'baseline'=2, 'hybrid'=3, 'manual'=4),
    score            UInt8,         -- 0..100, semántica en E00 §4.3.3
    severity         Enum8('info'=1, 'low'=2, 'medium'=3, 'high'=4, 'critical'=5),
    confidence       Float32,       -- 0.0..1.0
    observed_value   Float64,       -- valor de la métrica primaria del detector
    threshold_value  Float64,       -- umbral que se cruzó (0 si method='baseline')
    -- Producto de los boosters/amortiguadores del detector (E00b D-25).
    -- 1.0 = sin ajuste. Multiplica al ratio para calcular el score, NUNCA a
    -- observed_value ni a threshold_value, que quedan crudos y auditables.
    -- El desglose por booster va en evidence.boosters. C-7: columna REAL,
    -- el motor la escribe siempre en el INSERT (E05 §5.1.1), nunca se apoya
    -- en este DEFAULT para decidir "sin ajuste".
    ratio_adjust     Float64 DEFAULT 1.0,
    baseline_value   Float64,       -- valor esperado por el perfil (0 si method='threshold')
    deviation_sigma  Float32,       -- (observed - baseline) / MAD (0 si method='threshold')

    -- ══ Supresión y trazabilidad ════════════════════════════════════════════
    -- 1 = el evento se registra pero NO genera acción. Razones: detector en
    -- modo shadow, regla de supresión, ventana de mantenimiento, cliente en
    -- allowlist, ingesta degradada (E00b D-26), score ajustado por debajo del
    -- piso de acción (E00b D-25).
    -- Se GUARDA igual: es la materia prima de la calibración.
    -- El enum CERRADO de suppress_reason lo fija E05 §5.5 (incluye
    -- 'ingest_degraded', 'below_action_score' y el genérico 'rule:<rule_name>').
    suppressed       UInt8,
    suppress_reason  LowCardinality(String),
    -- JSON con lo específico del detector. Contrato de forma en E00 §4.3.5.
    evidence         String         CODEC(ZSTD(3)),
    -- Instancia del motor que lo produjo (para depurar despliegues mixtos).
    engine_instance  LowCardinality(String)
)
ENGINE = ReplacingMergeTree(detected_at)
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, attack_class, src_ip, detector_id, event_id)
TTL window_start + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- ═══════════════════════════════════════════════════════════════════════════
-- isp.det_cases -- el ciclo de vida (E00 §4.3.6, DDL LITERAL, no se modifica)
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS isp.det_cases
(
    case_id        UUID,
    -- El caso agrupa por (src_ip, attack_class). Un mismo cliente escaneando
    -- Y spameando genera DOS casos: se mitigan distinto.
    src_ip         IPv6,
    customer_id    LowCardinality(String),
    attack_class   Enum8('scan'=1, 'smtp_spam'=2, 'ddos_out'=3, 'reflection'=4,
                         'amplification'=5, 'anomaly'=6, 'policy'=7, 'other'=99),

    opened_at      DateTime('UTC'),
    updated_at     DateTime64(3, 'UTC'),      -- versión del ReplacingMergeTree
    last_event_at  DateTime('UTC'),
    closed_at      DateTime('UTC'),            -- epoch 0 si sigue abierto

    -- open       → hay evidencia, todavía no alcanza para accionar
    -- confirmed  → cruzó el umbral de acción; el mitigador lo va a tomar
    -- mitigating → el mitigador lo está aplicando
    -- mitigated  → aplicado en todos los routers destino
    -- expired    → sin eventos nuevos por SEC_DETECT_CASE_IDLE; el bloqueo caduca solo
    -- dismissed  → un operador (o una regla) lo declaró falso positivo
    state          Enum8('open'=1, 'confirmed'=2, 'mitigating'=3, 'mitigated'=4,
                         'expired'=5, 'dismissed'=6),
    dismiss_reason LowCardinality(String),

    event_count    UInt32,
    detectors      Array(LowCardinality(String)),   -- distintos detectores que aportaron
    -- E05 Q10: las FAMILIAS que aportaron, congeladas al momento de la decisión.
    -- No se deriva de `detectors` cruzando dim_detectors: eso consultaría el
    -- presente, y si alguien reclasifica la Family de un detector, todos los casos
    -- históricos cambian de respuesta. La corroboración por familias distintas (D6)
    -- es lo que autoriza una mitigación; tiene que quedar escrita, no recalculable.
    detector_families Array(LowCardinality(String)),
    peak_score     UInt8,
    peak_pps       Float64,
    peak_bps       Float64,
    peak_uniq_dst  UInt64,
    victims_sample Array(IPv6),                     -- hasta 50
    victim_count   UInt64,

    mitigation_count UInt16,
    last_action    LowCardinality(String),
    notes          String
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(opened_at)
ORDER BY (src_ip, attack_class, case_id)
TTL opened_at + INTERVAL 180 DAY DELETE;

-- ═══════════════════════════════════════════════════════════════════════════
-- isp.ops_detect_state -- watermark, bitácora y huella (E05 §5.2)
-- ═══════════════════════════════════════════════════════════════════════════
-- Una fila por (detector_id, window_start). Cumple tres funciones:
--   1. watermark: max(window_end) evaluado por detector, para status IN
--      ('ok','skipped') -- 'error'/'timeout' NO avanzan el watermark (se
--      reintenta la ventana) y 'pending' TAMPOCO cuenta (D-30): es trabajo
--      atrasado, no progreso.
--   2. bitácora de corridas: costo, duración, resultado, query_id
--   3. huella de datos para decidir revisita (E05 §4.2)
--
-- La cola de pendientes del replay del WAL se lee con
-- `SELECT ... FROM isp.ops_detect_state FINAL WHERE status = 'pending'`, y el
-- cursor del replayer vive en la misma tabla con una fila sintética
-- (detector_id = '__replay_cursor__').
CREATE TABLE IF NOT EXISTS isp.ops_detect_state
(
    detector_id       LowCardinality(String),
    detector_version  UInt16,
    window_start      DateTime('UTC'),
    window_end        DateTime('UTC'),
    evaluated_at      DateTime64(3, 'UTC'),   -- versión del ReplacingMergeTree
    eval_count        UInt8,                  -- 1 la primera vez; +1 por revisita

    -- Huella de la fuente al momento de evaluar
    src_rows          UInt64,
    src_last_inserted DateTime64(3, 'UTC'),

    -- Resultado
    status            Enum8('ok'=1, 'error'=2, 'timeout'=3, 'skipped'=4,
                            'stale_ingest'=5, 'breaker_open'=6, 'degraded'=7,
                            -- D-30: encolada por el replayer del WAL, todavía sin evaluar
                            'pending'=8),
    error_code        LowCardinality(String), -- 'SEC-DET-001', '' si ok
    error_message     String,

    findings          UInt32,   -- filas devueltas por la query
    events_emitted    UInt32,   -- escritas en det_events con suppressed=0
    events_suppressed UInt32,
    truncated         UInt8,

    duration_ms       UInt32,
    rows_read         UInt64,
    bytes_read        UInt64,
    memory_peak_bytes UInt64,
    query_id          String,
    engine_instance   LowCardinality(String)
)
ENGINE = ReplacingMergeTree(evaluated_at)
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (detector_id, window_start)
TTL window_start + INTERVAL 14 DAY DELETE;

-- ═══════════════════════════════════════════════════════════════════════════
-- isp.v_det_events / isp.v_det_cases -- E05 §5.4 (texto canónico, ver nota de
-- cabecera: la escritura de estas dos vistas es entregable de esta task, no
-- de T-074/43_v_det.sql).
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_det_events
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
    event_id, case_id,
    window_start, window_end, detected_at,
    detector_id, detector_version, attack_class, attack_subtype,
    src_ip, isp_ip_str(src_ip) AS src_ip_str, src_ip_version, customer_id, src_prefix, src_asn,
    dst_kind,
    dst_ip, isp_ip_str(dst_ip) AS dst_ip_str, dst_port, proto, dst_asn, dst_cc,
    top_dsts, arrayMap(x -> isp_ip_str(x), top_dsts) AS top_dsts_str, top_dst_packets,
    packets, bytes, flows, pps, bps,
    uniq_dst_ips, uniq_dst_ports, uniq_dst_asns, syn_packets,
    sampling_max, cardinality_exact,
    method, score, severity, confidence,
    observed_value, threshold_value, baseline_value, deviation_sigma,
    observed_value / nullIf(threshold_value, 0) AS ratio,
    -- D-25 / C-7: ratio_adjust es una COLUMNA REAL de isp.det_events
    -- (Float64 DEFAULT 1.0), no un campo derivado del JSON. Se lee directo.
    -- El desglose por booster sí vive en evidence.boosters, que es otra
    -- cosa: el producto se persiste para que el score sea reconstruible sin
    -- parsear JSON.
    ratio_adjust,
    ratio * ratio_adjust AS ratio_adj,
    -- D-26: salud de la ingesta de la ventana, para poder filtrar en el panel.
    toUInt8OrDefault(JSONExtractRaw(JSONExtractRaw(evidence, 'ingest'), 'degraded'), 0)
                                                AS ingest_degraded,
    toFloat64OrDefault(JSONExtractRaw(JSONExtractRaw(evidence, 'ingest'), 'shed_ratio'), 0.0)
                                                AS ingest_shed_ratio,
    suppressed, suppress_reason,
    evidence, engine_instance,
    toUInt32(window_end - window_start) AS window_seconds
FROM isp.det_events FINAL;

CREATE OR REPLACE VIEW isp.v_det_cases
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
    case_id,
    src_ip, isp_ip_str(src_ip) AS src_ip_str, customer_id, attack_class,
    opened_at, updated_at, last_event_at, closed_at, state, dismiss_reason,
    event_count, detectors, length(detectors) AS detector_count,
    peak_score, peak_pps, peak_bps, peak_uniq_dst,
    victims_sample, arrayMap(x -> isp_ip_str(x), victims_sample) AS victims_sample_str,
    victim_count, mitigation_count, last_action, notes,
    if(closed_at = toDateTime(0), now() - opened_at, closed_at - opened_at) AS duration_s,
    state IN ('open','confirmed','mitigating') AS is_active,
    -- Corroboración: familias de evidencia distintas entre los detectores del caso.
    -- E11 la usa para habilitar (o no) la mitigación total del cliente.
    -- D-35 + C-6: dict_detector_family es COMPLEX_KEY_HASHED porque su clave es
    -- `detector_id String`, y ClickHouse admite LAYOUT(HASHED()) SOLO con clave
    -- simple numérica (UInt64). Una clave String en HASHED no compila sin una
    -- clave sustituta numérica que no existe. Por lo tanto el dictGet va SIEMPRE
    -- con tuple(). Escrito sin tupla no compila, y una vista que no compila deja
    -- a E11 sin distinct_families. Resuelto a favor de E05 por C-6.
    -- Q10 (decidida): `detector_families` se persiste en det_cases (E00 §4.3.6), y
    -- esta vista deriva el conteo de la COLUMNA, no del dictGet. El dictGet
    -- consultaba el presente: si alguien reclasifica la Family de un detector,
    -- todos los casos históricos cambiaban de respuesta y la auditoría de por qué
    -- se autorizó una mitigación dejaba de ser reconstruible.
    length(arrayDistinct(detector_families))               AS distinct_families,
    -- Modo efectivo de los detectores del caso (E05 §5.8), para que E11 no tenga que
    -- leer la config del motor para saber si puede accionar.
    arrayDistinct(arrayMap(
        d -> dictGetOrDefault('isp.dict_detector_family', 'mode', tuple(d), 'shadow'),
        detectors)) AS detector_modes
FROM isp.det_cases FINAL;
