-- 50_mit.sql [E11]
--
-- T-090 (E11-T01) -- E11 §5.1, §5.4, §5.4.1 · E00 §4.3.7 · E00d F-6 ·
-- E00f H-3 · E00b D-34, D-36, D-39.
--
-- isp.mit_actions (la auditoría de lo que el mitigador decidió y aplicó) más
-- CUATRO de las cinco vistas v_mit_* de E11 §5.4: v_mit_actions,
-- v_mit_blocks_active, v_mit_customer_history, v_mit_quality_30d.
--
-- La quinta, v_mit_router_events, NO va acá: su SELECT es "FROM
-- isp.ops_audit", y ops_audit se declara en 90_ops_audit.sql -- un número
-- MAYOR que 50 (D-36: el DDL canónico de ops_audit es de E12 §5.4, esta
-- épica solo inserta). Por H-1 (ClickHouse resuelve el cuerpo de una vista
-- al CREATE), declarar v_mit_router_events acá haría abortar este archivo
-- entero y con él 6x/7x/9x/95_roles_grants.sql. v_mit_router_events se crea
-- en 94c_ops_views.sql (T-091, E12), que corre después de 90_ y antes de 95_.
--
-- Todo lo que sigue lee isp.mit_actions con FINAL (ReplacingMergeTree por
-- created_at) o a través de una de estas vistas -- nunca la tabla base a
-- secas (E11 §5.1, párrafo final).
--
-- La UDF de formateo de IP es isp_ip_str, SIN punto y con prefijo isp_
-- (D-34): ClickHouse no admite '.' en un nombre de función, así que
-- isp.ip_str( e ip_str( a secas son errores -- E03 §8.1 los caza con un
-- grep. isp_ip_str ya existe (00_database.sql), un número menor que este.

-- ═══════════════════════════════════════════════════════════════════════════
-- isp.mit_actions -- E00 §4.3.7 (primer bloque, LITERAL, no se modifica) +
-- las columnas que E11 agrega (segundo bloque, permitido por E00: "puede
-- agregar columnas, no quitar ni renombrar").
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS isp.mit_actions
(
    -- ── Contrato E00 §4.3.7 (literal) ──────────────────────────────────────
    action_id     UUID,
    case_id       UUID,
    event_id      UUID,                 -- evento que la disparó
    created_at    DateTime64(3, 'UTC'),
    applied_at    DateTime64(3, 'UTC'), -- epoch 0 si no se aplicó
    expires_at    DateTime('UTC'),

    src_ip        IPv6,
    customer_id   LowCardinality(String),
    dst_ip        IPv6,                 -- '::' si la acción no es pareada
    proto         UInt8,
    dst_port      UInt16,

    -- block_pair    = par src+dst (bloqueo quirúrgico)
    -- block_service = src + proto/puerto (ej. cortar solo SMTP saliente)
    -- block_src     = cliente completo (requiere doble corroboración)
    -- rate_limit    = marcado para cola/limitación
    -- observe       = dry-run: se calculó todo, no se tocó el router
    action        Enum8('observe'=0, 'block_pair'=1, 'block_service'=2,
                        'block_src'=3, 'rate_limit'=4, 'unblock'=5),
    -- ok        = aplicado en TODOS los routers destino
    -- partial   = aplicado en algunos
    -- failed    = en ninguno. El PRIMER reintento es inmediato (el tick
    --             siguiente) y no integra cooldowns, igual que antes; a
    --             partir del segundo fallo consecutivo de la MISMA entrada,
    --             retryBackoff (internal/mitigate/retrybackoff.go) lo
    --             espacia exponencialmente hasta
    --             SEC_MIT_RETRY_BACKOFF_MAX_SECONDS. El contrato anterior
    --             decía "reintento rápido" a secas y era literal: una
    --             entrada que fallaba se reintentaba cada
    --             SEC_MIT_TICK_SECONDS indefinidamente -- 25.638 filas
    --             failed en 24 h contra un solo destino, medido en
    --             producción.
    -- skipped   = un safeguard lo frenó a propósito
    -- dry_run   = el detector/mitigador está en modo observación
    status        Enum8('ok'=1, 'partial'=2, 'failed'=3, 'skipped'=4, 'dry_run'=5),
    skip_reason   LowCardinality(String),

    routers_total   UInt16,
    routers_ok      UInt16,
    address_list    LowCardinality(String),
    timeout_seconds UInt32,               -- <= 86400 salvo aprobación humana (O6)
    score         UInt8,
    detector_id   LowCardinality(String),
    details       String CODEC(ZSTD(3)),  -- JSON

    -- ── Agregado por E11 ───────────────────────────────────────────────────
    -- Identidad del plan: determinística (§4.3). Varias filas comparten
    -- plan_id cuando el mismo plan se reintentó tras un 'failed', o cuando
    -- pasó SEC_MIT_AUDIT_HEARTBEAT_SECONDS sin que su huella auditable
    -- cambiara (latido de auditGate, internal/mitigate/auditgate.go). Este
    -- contrato estuvo VIOLADO hasta que existió esa guarda: el lazo de
    -- auditoría escribía una fila por caso accionable en CADA tick, así que
    -- un bloqueo sano de 40 minutos acumulaba 474 filas con el mismo
    -- plan_id. Cualquier consumidor que cuente filas en vez de
    -- uniqExact(case_id) tiene que asumir esa historia en los datos viejos.
    plan_id       UUID,
    -- Mismo Enum8 CERRADO que det_events.attack_class (E00 §4.3.1). Necesario
    -- para que el cooldown y la escalera puedan agrupar por
    -- (src_ip, attack_class) sin joinear contra det_cases.
    attack_class  Enum8('scan'=1,'smtp_spam'=2,'ddos_out'=3,'reflection'=4,
                        'amplification'=5,'anomaly'=6,'policy'=7,'other'=99),
    -- Perfil de servicio: 'smtp' | 'auto:6:445' | 'auto:17:11211' | ''.
    -- NO existe el valor 'reflector_udp' (E00b D-32): el perfil de reflector
    -- es por puerto. dst_port arriba lleva el puerto REPRESENTATIVO del
    -- perfil (25 para smtp); el conjunto completo va en details.plan.ports.
    service       LowCardinality(String) DEFAULT '',
    ip_version    UInt8 DEFAULT 0,          -- 4 | 6
    escalation_level UInt8 DEFAULT 0,       -- 0..3 (§4.7)
    is_renewal    UInt8 DEFAULT 0,          -- 1 = solo refrescó timeout
    mode          Enum8('off'=0,'shadow'=1,'alert'=2,'mitigate'=3) DEFAULT 'shadow',
    -- Quién. Igual criterio que ops_audit de E04.
    actor         LowCardinality(String) DEFAULT 'system',
    actor_source  Enum8('system'=1,'cli'=2,'api'=3) DEFAULT 'system',
    reason_text   String DEFAULT '',        -- obligatorio en unblock y block manual
    -- Resultado por router: [{"name":..,"result":"ok|failed","existed":bool,"ms":int}]
    -- DEFAULT antes de CODEC (el orden inverso es un error de sintaxis, no
    -- de semántica; ver 90_ops_audit.sql.details para el mismo caso).
    routers_detail String DEFAULT '' CODEC(ZSTD(3)),
    notified      UInt8 DEFAULT 0,
    engine_instance LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (created_at, src_ip, action, action_id)
-- toDateTime(created_at): TTL exige DateTime/Date, no DateTime64 -- mismo
-- patrón que 10_flows_raw.sql y 90_ops_audit.sql (TTL toDateTime(...) + ...).
-- El contrato literal de E00 §4.3.7 escribe "TTL created_at + ..."; acá se
-- envuelve para que el CREATE TABLE compile contra ClickHouse 24.8 real, sin
-- cambiar la retención (365 días) ni la columna.
TTL toDateTime(created_at) + INTERVAL 365 DAY DELETE;

-- ORDER BY y ENGINE son los de E00, sin cambios. Lecturas SIEMPRE con FINAL
-- o por las vistas de abajo.

-- ═══════════════════════════════════════════════════════════════════════════
-- v_mit_actions -- todas las acciones, legibles. Es la base de los paneles
-- de E10 (arista dura C-19: un nombre distinto no degrada el panel, lo deja
-- sin cargar).
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_mit_actions
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
    action_id, plan_id, case_id, event_id,
    created_at, applied_at, expires_at,
    src_ip, isp_ip_str(src_ip) AS src_ip_str, ip_version, customer_id,
    dst_ip, isp_ip_str(dst_ip) AS dst_ip_str, proto, dst_port, service,
    attack_class, action, status, skip_reason, mode,
    escalation_level, is_renewal,
    routers_total, routers_ok, address_list, timeout_seconds,
    score, detector_id, actor, actor_source, reason_text,
    details, routers_detail, engine_instance,
    -- ── Las TRES derivadas del contrato de E10 §5.3, transcriptas carácter
    --    por carácter (E00d F-6). No se renombran ni se envuelven: el test
    --    de E10 §8.3 punto 2 es un DESCRIBE contra esta forma exacta.
    if(expires_at > now(), 1, 0)                                  AS is_active,     -- UInt8, no Bool
    greatest(toInt64(expires_at) - toInt64(now()), 0)             AS expires_in_s,
    dateDiff('millisecond', created_at, applied_at)               AS apply_latency_ms,
    -- Extra de E11: 0 cuando applied_at quedó en epoch (plan skipped/dry_run/
    -- failed), que es el único caso en que apply_latency_ms no significa nada.
    if(applied_at = toDateTime64(0, 3), 0, 1)                     AS is_applied
FROM isp.mit_actions FINAL;

-- ═══════════════════════════════════════════════════════════════════════════
-- v_mit_blocks_active -- estado vigente: una fila por (src_ip, address_list)
-- que sigue bloqueada. Es "reconstruible desde mit_actions" (E00 §2.3): el
-- mitigador no persiste estado.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_mit_blocks_active
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
    src_ip, isp_ip_str(src_ip) AS src_ip_str, customer_id, address_list,
    argMax(action, created_at)           AS last_action,
    argMax(case_id, created_at)          AS case_id,
    argMax(attack_class, created_at)     AS attack_class,
    argMax(detector_id, created_at)      AS detector_id,
    argMax(score, created_at)            AS score,
    argMax(expires_at, created_at)       AS expires_at,
    argMax(escalation_level, created_at) AS escalation_level,
    max(created_at)                      AS last_change_at,
    -- E00f H-3 (misma clase que E00e G-4a): acá NO se puede repetir
    -- argMax(expires_at, created_at). El alias de la línea de arriba es
    -- global al SELECT y gana sobre la columna (prefer_column_name_to_alias
    -- = 0, el default), así que el argMax interno se expandiría a
    -- argMax(argMax(...), created_at) y la vista no se crearía:
    -- ILLEGAL_AGGREGATION en este archivo y el instalador aborta ahí. Se
    -- referencia el alias, que se sustituye una sola vez.
    dateDiff('second', now(), expires_at) AS ttl_remaining_s
FROM isp.mit_actions FINAL
WHERE status IN ('ok', 'partial')
  AND created_at >= now() - INTERVAL 8 DAY
GROUP BY src_ip, customer_id, address_list
HAVING last_action != 'unblock' AND expires_at > now();

-- ═══════════════════════════════════════════════════════════════════════════
-- v_mit_customer_history -- historial completo de un cliente. La consulta
-- del reclamo (§4.10, paso 2).
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_mit_customer_history
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
    a.src_ip_str, a.customer_id, a.created_at, a.action, a.status, a.skip_reason,
    a.attack_class, a.detector_id, a.score, a.escalation_level,
    a.timeout_seconds, a.expires_at, a.actor, a.reason_text, a.case_id,
    c.state AS case_state, c.event_count, c.peak_score, c.victim_count
FROM isp.v_mit_actions AS a
LEFT JOIN isp.v_det_cases AS c USING (case_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- v_mit_quality_30d -- O5: acciones sobre casos que después se descartaron.
-- Es EL número de calidad.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_mit_quality_30d
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
    toStartOfDay(a.created_at)                                  AS day,
    a.attack_class                                              AS attack_class,
    a.detector_id                                               AS detector_id,
    uniqExactIf(a.case_id, a.status IN ('ok','partial'))         AS cases_blocked,
    uniqExactIf(a.case_id, a.status IN ('ok','partial')
                           AND c.state = 'dismissed')            AS cases_dismissed,
    uniqExactIf(a.case_id, a.status = 'dry_run')                 AS cases_dry_run,
    round(100.0 * uniqExactIf(a.case_id, a.status IN ('ok','partial') AND c.state = 'dismissed')
          / nullIf(uniqExactIf(a.case_id, a.status IN ('ok','partial')), 0), 3) AS dismissed_pct
FROM isp.mit_actions AS a FINAL
LEFT JOIN isp.det_cases AS c FINAL USING (case_id)
WHERE a.created_at >= now() - INTERVAL 30 DAY
  AND a.action != 'unblock'
GROUP BY day, attack_class, detector_id;
