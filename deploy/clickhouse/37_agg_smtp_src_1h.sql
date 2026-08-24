-- 37_agg_smtp_src_1h.sql [E07]
--
-- T-071 (E07-T26) -- E07 §5.4 · E00b D-8, D-9 · E00c C-4, C-13, C-14, C-15 ·
-- E00d F-5.
--
-- Rollup horario por origen de isp.agg_smtp_sessions, con TTL de 400 días.
-- Existe para tres consumidores que necesitan más historia de la que
-- agg_smtp_sessions retiene (3 días): el baselining por hora del día de E09,
-- el panel histórico de E10 y el reporte de calibración de E12. Los
-- detectores smtp.* de E07 (fase 1, en línea) NO leen esta tabla -- ver
-- internal/detect/smtp más abajo y el test que lo verifica. Depende de
-- 35_agg_smtp_sessions.sql.
--
-- La MV que la puebla es una MV ENCADENADA (dispara sobre cada INSERT hacia
-- isp.agg_smtp_sessions, no sobre flows_raw); sigue ADR-008: sin JOIN, sin
-- subconsulta que lea otra tabla, sin dictGet.
--
-- Trampa principal (D-9 / E00c C-4): sampling_max_state se lee de agg_smtp_sessions
-- con maxMergeState(sampling_max_state) -- NO maxState(sampling_max_state), que
-- construiría un estado de estados, ni maxState(sampling_applied), que ni
-- siquiera compila acá (esa columna es de flows_raw). Con el combinador
-- equivocado el CREATE MATERIALIZED VIEW da UNKNOWN_IDENTIFIER y, por ser una
-- MV, el error es de clase `schema` y DETIENE EL SINK.
--
-- Segunda trampa (E00c C-13): un WITH que define "hour" como
-- toStartOfHour(window_start) NO alcanza si la lista del SELECT de ESE MISMO
-- nivel hace "hour AS window_start": el alias "window_start" queda definido
-- en el mismo scope que la columna real "window_start" que el WITH consume,
-- ClickHouse resuelve la ambigüedad a favor del alias (prefer_column_name_to_alias
-- = 0, el default) y "hour" termina expandiéndose a
-- toStartOfHour(toStartOfHour(window_start)) recursivo -> CYCLIC_ALIASES,
-- exactamente el mismo síntoma que si se hubiera escrito
-- "toStartOfHour(window_start) AS window_start ... GROUP BY window_start" sin
-- ningún alias intermedio. La solución, igual que el intercambio de puntas de
-- 35_agg_smtp_sessions.sql (G-4b): el bucketing (SIN agregar) vive en una
-- subconsulta con nombre propio ("hour"), que no menciona "window_start" en
-- ningún punto de su propio scope; el GROUP BY y las agregaciones van AFUERA,
-- leyendo esa subconsulta, y ahí la proyección final "hour AS window_start"
-- ya no tiene ninguna expresión que re-resolver -- "hour" es una columna lisa
-- del FROM, no una expresión. ADR-008 prohíbe una subconsulta que lea OTRA
-- tabla; esta sigue leyendo isp.agg_smtp_sessions, así que no lo viola.
--
-- Única divergencia deliberada contra el texto literal de E07 §5.4:
-- uniq_dst_asns_state usa uniqCombined(12), no el uniqCombined(17) que el
-- documento declara. E03 §4.6.2 fija (12) para esta columna en TODO el
-- esquema (excepción consciente: el dominio de ASN es ~90.000 valores) y
-- agg_src_1m ya la declara así; con (17) acá, TestMergeCallsMatchDeclaredStateType
-- (E00c C-2/D-9) falla porque el mismo nombre de columna de estado no puede
-- tener dos tipos distintos en el esquema. Ver la nota de la columna, abajo.

CREATE TABLE IF NOT EXISTS isp.agg_smtp_src_1h
(
    window_start        DateTime('UTC'),          -- toStartOfHour(window_start)
    src_ip              IPv6,
    port_class          Enum8('mta'=1,'msa'=2),
    dst_scope           Enum8('unknown'=0,'customer'=1,'infra'=2,'external'=3),
    ip_version          SimpleAggregateFunction(any, UInt8),
    -- max y NO any (E00c C-15, mismo criterio que agg_smtp_sessions en
    -- 35_agg_smtp_sessions.sql): en el merge, cualquier customer_id no vacío
    -- tiene que ganarle a ''. La MV lo puebla con maxSimpleState(customer_id).
    customer_id         SimpleAggregateFunction(max, LowCardinality(String)),

    packets_out         SimpleAggregateFunction(sum, UInt64),
    bytes_out           SimpleAggregateFunction(sum, UInt64),
    packets_in          SimpleAggregateFunction(sum, UInt64),
    bytes_in            SimpleAggregateFunction(sum, UInt64),
    -- OJO CON EL NOMBRE (E00d F-5): esta columna se puebla con
    -- sumSimpleState(chunks), o sea cuenta REGISTROS DE FLUJO -- lo que
    -- agg_smtp_sessions llama "chunks" --, NO las filas que v_smtp_sessions
    -- llama "fragments". NO renombrar: es una migración de esquema sobre una
    -- tabla con TTL de 400 días y con consumidores en E09/E10/E12. La
    -- cobertura horaria de flags es flags_valid_chunks / fragments ACÁ
    -- (porque acá "fragments" ya son registros) y flags_valid_chunks / chunks
    -- en v_smtp_sessions, y las dos expresiones dan la MISMA fracción. Si
    -- alguien la "arregla" a chunks, reintroduce F-5 en el rollup.
    fragments             SimpleAggregateFunction(sum, UInt64),
    approx_sessions_state AggregateFunction(uniqCombined(17), Tuple(IPv6, UInt16)),
    uniq_dst_ips_state    AggregateFunction(uniqCombined(17), IPv6),
    -- Divergencia deliberada contra el texto literal de E07 §5.4, que declaraba
    -- uniqCombined(17) acá: E03 §4.6.2 fija uniqCombined(12) para
    -- uniq_dst_asns_state en TODO el esquema (agg_src_1m, agg_dst_svc_1m/1h) --
    -- excepción consciente porque el dominio de ASN es ~90.000 valores y (12)
    -- alcanza de sobra con un estado más chico. Es el mismo nombre de columna
    -- en varias tablas (D-9): TestMergeCallsMatchDeclaredStateType exige un
    -- solo tipo para "uniq_dst_asns_state" en todo el esquema, o divergiría en
    -- silencio para cualquier vista futura que compare los dos agregados.
    uniq_dst_asns_state   AggregateFunction(uniqCombined(12), UInt32),
    syn_only_chunks     SimpleAggregateFunction(sum, UInt64),
    established_chunks  SimpleAggregateFunction(sum, UInt64),
    flags_valid_chunks  SimpleAggregateFunction(sum, UInt64),
    -- D-9, igual que en agg_smtp_sessions: la ÚNICA columna AggregateFunction
    -- de estado de sampling de la tabla. Se puebla con
    -- maxMergeState(sampling_max_state) -- ver la nota de cabecera.
    sampling_max_state  AggregateFunction(max, UInt32)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, src_ip, port_class, dst_scope)
TTL window_start + INTERVAL 400 DAY DELETE
-- D-8: OBLIGATORIO, misma razón que 35_agg_smtp_sessions.sql -- sin esto un
-- reintento del sink infla este rollup y el baseline de E09 se construye
-- sobre volúmenes duplicados, en silencio.
SETTINGS non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW isp.mv_agg_smtp_src_1h TO isp.agg_smtp_src_1h AS
SELECT
    -- El bucketing ya viene resuelto por la subconsulta, con nombre propio
    -- ("hour"). Acá solo se proyecta al nombre del DDL -- mismo recurso que
    -- mv_agg_smtp_sessions usa para cli_ip/srv_ip (G-4b).
    hour                                                   AS window_start,
    src_ip,
    port_class,
    dst_scope,

    anySimpleState(ip_version)                            AS ip_version,
    -- max, no any (E00c C-15): mismo motivo que 35_agg_smtp_sessions.sql, o
    -- el rollup horario vuelve a perder el abonado que el minuto sí tenía.
    maxSimpleState(customer_id)                           AS customer_id,

    sumSimpleState(packets_out)                           AS packets_out,
    sumSimpleState(bytes_out)                             AS bytes_out,
    sumSimpleState(packets_in)                            AS packets_in,
    sumSimpleState(bytes_in)                               AS bytes_in,
    -- El nombre engaña (E00d F-5): la fuente es agg_smtp_sessions.chunks, o
    -- sea REGISTROS de flujo, no las filas que v_smtp_sessions llama
    -- "fragments". Ver la nota de la columna en el CREATE TABLE de arriba.
    sumSimpleState(chunks)                                AS fragments,

    -- Identidad aproximada de la sesión: una fila de origen es una 5-tupla
    -- por minuto, y approx_sessions es aproximado a propósito (E07 §5.4): la
    -- costura exacta no se puede hacer en una MV y, para un perfil horario,
    -- un error del orden de 1 % es irrelevante.
    uniqCombinedState(17)((dst_ip, src_port))             AS approx_sessions_state,
    uniqCombinedState(17)(dst_ip)                         AS uniq_dst_ips_state,
    -- (12), no (17): ver la nota de la columna en el CREATE TABLE de arriba.
    uniqCombinedState(12)(dst_asn)                        AS uniq_dst_asns_state,

    sumSimpleState(syn_only_chunks)                       AS syn_only_chunks,
    sumSimpleState(established_chunks)                    AS established_chunks,
    sumSimpleState(flags_valid_chunks)                    AS flags_valid_chunks,

    -- D-9 / E00c C-4: la fuente YA ES un estado (AggregateFunction(max,
    -- UInt32)), no un valor. maxMergeState fusiona los estados de la hora y
    -- vuelve a serializar UN estado -- es el combinador correcto cuando el
    -- destino es otra columna de estado. maxState(sampling_max_state) daría
    -- un estado de estados (UNKNOWN_IDENTIFIER al aplicar, clase `schema`,
    -- DETIENE EL SINK); maxState(sampling_applied) ni siquiera compila acá,
    -- porque esa columna es de flows_raw y no de agg_smtp_sessions.
    maxMergeState(sampling_max_state)                     AS sampling_max_state
FROM
(
    -- El bucketing vive ACÁ y solo acá, con nombre propio ("hour"), sin
    -- mencionar "window_start" en ningún punto de este scope (E00c C-13): es
    -- lo que evita el ciclo. Sin agregar todavía -- la agregación va afuera.
    -- La subconsulta NO lee otra tabla (ADR-008): el FROM sigue siendo
    -- isp.agg_smtp_sessions.
    SELECT
        toStartOfHour(window_start) AS hour,
        src_ip,
        port_class,
        dst_scope,
        ip_version,
        customer_id,
        packets_out,
        bytes_out,
        packets_in,
        bytes_in,
        chunks,
        dst_ip,
        src_port,
        dst_asn,
        syn_only_chunks,
        established_chunks,
        flags_valid_chunks,
        sampling_max_state
    FROM isp.agg_smtp_sessions
)
GROUP BY hour, src_ip, port_class, dst_scope;
