-- 35_agg_smtp_sessions.sql [E03]
--
-- T-052 (E03-T11) -- E03 §3 D6, §4.5.7, §4.6.2 · E00b D-1, D-8, D-9 ·
-- E00c C-4, C-15 · E00e G-4b · E00f H-4.
--
-- Transcripción literal de E07 §4.2 / §5.1 (D-1: E07 gana este DDL). El
-- bloque ejecutable es idéntico carácter por carácter, tras normalizar
-- comentarios, al de test/schema/smtp_ddl_test.go (T-051); ese test lo
-- verifica. Depende de 10_flows_raw.sql.
--
-- El CREATE MATERIALIZED VIEW va SIN IF NOT EXISTS -- la idempotencia del
-- instalador es por sha256 en ops_schema_version, no por IF NOT EXISTS
-- (E03 §4.9.2). Trampa principal (G-4b): el intercambio de puntas vive en la
-- subconsulta con nombres propios (cli_*/srv_*); escrito en un solo nivel es
-- CYCLIC_ALIASES y el CREATE no compila -- se lleva puesto TODO el bloque
-- posterior del instalador (36, 37, 38, el 4x de E05, el 5x de E11, el 6x de
-- E09, el panel y los GRANTs).

CREATE TABLE IF NOT EXISTS isp.agg_smtp_sessions
(
    -- BUCKET. toStartOfMinute(ts_received). Arregla la deuda #7/#22: sin esto,
    -- el reuso de puerto efímero fusiona sesiones distintas en una fila.
    window_start        DateTime('UTC'),

    -- src_ip es SIEMPRE el cliente y dst_ip SIEMPRE el servidor SMTP, sin importar
    -- el sentido del registro de flujo que originó la fila (D3).
    src_ip              IPv6,
    dst_ip              IPv6,
    src_port            UInt16,          -- efímero, del cliente
    dst_port            UInt16,          -- de servicio: 25 | 465 | 587 | 2525
    dst_scope           Enum8('unknown'=0,'customer'=1,'infra'=2,'external'=3),
    port_class          Enum8('mta'=1,'msa'=2),

    ip_version          SimpleAggregateFunction(any, UInt8),
    -- max y NO any (E00c C-15): en el merge, cualquier customer_id no vacío tiene
    -- que ganarle a ''. La MV lo puebla con maxSimpleState(customer_id). Ver R4c.
    customer_id         SimpleAggregateFunction(max, LowCardinality(String)),
    dst_asn             SimpleAggregateFunction(any, UInt32),
    dst_cc              SimpleAggregateFunction(any, LowCardinality(String)),

    -- Volumen. packets_*/bytes_* YA vienen escalados por sampling (E00 §4.2).
    packets_out         SimpleAggregateFunction(sum, UInt64),
    bytes_out           SimpleAggregateFunction(sum, UInt64),
    packets_in          SimpleAggregateFunction(sum, UInt64),
    bytes_in            SimpleAggregateFunction(sum, UInt64),
    -- Verificado contra ClickHouse 24.8 real (§8.2): sum() SIEMPRE ensancha un
    -- entero sin signo de menos de 64 bits a UInt64, y a diferencia de
    -- AggregateFunction, SimpleAggregateFunction exige que el tipo declarado
    -- coincida EXACTO con el que la función devuelve -- "CREATE TABLE ...
    -- SimpleAggregateFunction(sum, UInt32)" falla con BAD_ARGUMENTS
    -- ("Incompatible data types between aggregate function 'sum' which
    -- returns UInt64 and column storage type UInt32") en TODOS los casos, no
    -- solo en este. Es la única divergencia deliberada contra el texto literal
    -- de E07 §5.1, que declaraba UInt32 acá: sin este cambio el CREATE TABLE
    -- no compila y nada de lo que sigue en el instalador se crea.
    chunks              SimpleAggregateFunction(sum, UInt64),   -- registros de flujo

    -- Reloj del EXPORTADOR: duración de la sesión (deuda #19).
    flow_start          SimpleAggregateFunction(min, DateTime64(3,'UTC')),
    flow_end            SimpleAggregateFunction(max, DateTime64(3,'UTC')),
    -- Reloj del COLLECTOR: solo diagnóstico de lag. NO se usa para duración.
    first_seen          SimpleAggregateFunction(min, DateTime64(3,'UTC')),
    last_seen           SimpleAggregateFunction(max, DateTime64(3,'UTC')),

    -- Derivadas de tcp_flags, solo del sentido saliente y solo si son válidas
    -- (ADR-012). UInt64 y no UInt32 por el mismo motivo que chunks, arriba.
    syn_only_chunks     SimpleAggregateFunction(sum, UInt64),
    established_chunks  SimpleAggregateFunction(sum, UInt64),
    rst_chunks          SimpleAggregateFunction(sum, UInt64),
    fin_chunks          SimpleAggregateFunction(sum, UInt64),
    flags_valid_chunks  SimpleAggregateFunction(sum, UInt64),

    -- ÚNICA AggregateFunction de la tabla (D-9). El sufijo _state es obligatorio
    -- por E00 §4.5.1 y el nombre y el tipo son los mismos que en agg_src_1m,
    -- agg_src_port_1m y agg_src_dst_svc_1m: un solo estado de sampling en todo
    -- el esquema. Se puebla con maxState(sampling_applied).
    sampling_max_state  AggregateFunction(max, UInt32)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (window_start, src_ip, dst_scope, port_class, dst_ip, dst_port, src_port)
TTL window_start + INTERVAL 3 DAY DELETE
SETTINGS index_granularity = 8192,
         -- D-8: OBLIGATORIO. Sin esto, insert_deduplication_token es un no-op en
         -- MergeTree no replicado y deduplicate_blocks_in_dependent_materialized_views
         -- no tiene dónde deduplicar: un reintento del sink infla este agregado y
         -- smtp.volume dispara sobre clientes normales durante un replay del WAL.
         non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW isp.mv_agg_smtp_sessions TO isp.agg_smtp_sessions AS
SELECT
    -- El intercambio de puntas ya viene resuelto por la subconsulta, con nombres
    -- propios (cli_*/srv_*). Acá solo se proyecta al nombre del DDL: src_ip SIEMPRE
    -- es el cliente y dst_ip SIEMPRE el servidor SMTP, sin importar el sentido del
    -- registro de flujo (D3).
    window_start,
    cli_ip                                                         AS src_ip,
    srv_ip                                                         AS dst_ip,
    cli_port                                                       AS src_port,
    srv_port                                                       AS dst_port,
    srv_scope                                                      AS dst_scope,
    port_class,

    anySimpleState(ip_version)                                     AS ip_version,
    -- E00c C-15: NO se fuerza a '' en la pata entrante. E04 §4.8.2 resuelve
    -- customer_id por la punta que ES cliente, así que en el registro inverso
    -- (MX externo → cliente) el valor YA es el del abonado. max, y no any,
    -- porque en el merge cualquier valor no vacío tiene que ganarle a ''.
    maxSimpleState(customer_id)                                    AS customer_id,
    anySimpleState(srv_asn)                                        AS dst_asn,
    anySimpleState(srv_cc)                                         AS dst_cc,

    sumSimpleState(if(fwd, packets, 0))                            AS packets_out,
    sumSimpleState(if(fwd, bytes,   0))                            AS bytes_out,
    sumSimpleState(if(fwd, 0, packets))                            AS packets_in,
    sumSimpleState(if(fwd, 0, bytes))                              AS bytes_in,
    sumSimpleState(toUInt32(1))                                    AS chunks,

    -- Reloj del EXPORTADOR: es lo único que puede medir duración (deuda #19).
    minSimpleState(ts_start)                                       AS flow_start,
    maxSimpleState(ts_end)                                         AS flow_end,
    -- Reloj del COLLECTOR: solo para diagnóstico de lag.
    minSimpleState(ts_received)                                    AS first_seen,
    maxSimpleState(ts_received)                                    AS last_seen,

    -- Flags, solo del sentido saliente y solo si el exportador las informó (ADR-012).
    sumSimpleState(toUInt32(fwd AND tcp_flags_valid = 1
                            AND bitAnd(tcp_flags, 0x12) = 0x02))   AS syn_only_chunks,
    sumSimpleState(toUInt32(fwd AND tcp_flags_valid = 1
                            AND bitAnd(tcp_flags, 0x10) != 0))     AS established_chunks,
    sumSimpleState(toUInt32(fwd AND tcp_flags_valid = 1
                            AND bitAnd(tcp_flags, 0x04) != 0))     AS rst_chunks,
    sumSimpleState(toUInt32(fwd AND tcp_flags_valid = 1
                            AND bitAnd(tcp_flags, 0x01) != 0))     AS fin_chunks,
    sumSimpleState(toUInt32(fwd AND tcp_flags_valid = 1))          AS flags_valid_chunks,

    -- ÚNICA columna AggregateFunction de la tabla, por D-9: la convención de
    -- E00 §4.5.1 reserva el sufijo _state para AggregateFunction y este estado
    -- es el que E03/E06/E08 comparten con el mismo nombre y tipo.
    maxState(sampling_applied)                                     AS sampling_max_state
FROM
(
    -- El intercambio de puntas vive ACÁ y solo acá, con nombres propios (E00e G-4b).
    -- En un solo nivel, if(fwd, src_ip, dst_ip) AS src_ip junto a
    -- if(fwd, dst_ip, src_ip) AS dst_ip define src_ip en términos de dst_ip y
    -- dst_ip en términos de src_ip: ciclo mutuo, CYCLIC_ALIASES, el CREATE no
    -- compila (misma clase que E00c C-13). Adentro cada expresión estrena nombre;
    -- afuera se proyecta al nombre del DDL. La subconsulta NO lee otra tabla: el
    -- FROM más interno sigue siendo isp.flows_raw, que es sobre lo que ClickHouse
    -- sustituye el bloque insertado (ADR-008, R8 de §5.1).
    WITH
        -- ¿el registro es el sentido cliente → servidor SMTP?
        (dst_port IN (25, 465, 587, 2525)) AS fwd
    SELECT
        fwd,
        toStartOfMinute(ts_received)                               AS window_start,
        if(fwd, src_ip,    dst_ip)                                 AS cli_ip,
        if(fwd, dst_ip,    src_ip)                                 AS srv_ip,
        if(fwd, src_port,  dst_port)                               AS cli_port,
        if(fwd, dst_port,  src_port)                               AS srv_port,
        if(fwd, dst_scope, src_scope)                              AS srv_scope,
        if(fwd, dst_asn,   src_asn)                                AS srv_asn,
        if(fwd, dst_cc,    src_cc)                                 AS srv_cc,
        if(srv_port = 25, 'mta', 'msa')                            AS port_class,
        ip_version,
        customer_id,
        packets,
        bytes,
        ts_start,
        ts_end,
        ts_received,
        tcp_flags,
        tcp_flags_valid,
        sampling_applied
    FROM isp.flows_raw
    WHERE proto = 6
      AND (
            -- saliente del cliente hacia un servidor SMTP
            (dst_port IN (25, 465, 587, 2525)
             AND src_scope = 'customer'
             AND flow_dir IN ('outbound', 'internal'))
         OR -- la respuesta del servidor a ese mismo cliente
            (src_port IN (25, 465, 587, 2525)
             AND dst_scope = 'customer'
             AND flow_dir IN ('inbound', 'internal'))
          )
)
GROUP BY window_start, cli_ip, srv_ip, cli_port, srv_port, srv_scope, port_class;

-- Vista de fragmentos, plana. Para diagnóstico y para el panel de bajo nivel
-- de E10 (E07 §5.2). La definición canónica de "sesión SMTP" completa vive en
-- v_smtp_sessions (38_v_smtp_sessions.sql, T-053), no acá.
--
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED sobre isp.agg_smtp_sessions al consultar esta vista,
-- verificado contra un ClickHouse 24.8 real -- una vista normal ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra, y el
-- GRANT SELECT sobre la vista misma no alcanza.
CREATE OR REPLACE VIEW isp.v_agg_smtp_sessions
SQL SECURITY DEFINER
AS
SELECT
    window_start, src_ip, dst_ip, src_port, dst_port, dst_scope, port_class,
    ip_version, customer_id, dst_asn, dst_cc,
    packets_out, bytes_out, packets_in, bytes_in, chunks,
    flow_start, flow_end, first_seen, last_seen,
    syn_only_chunks, established_chunks, rst_chunks, fin_chunks, flags_valid_chunks,
    -- D-9: la columna es AggregateFunction; sin GROUP BY se resuelve fila a fila.
    finalizeAggregation(sampling_max_state) AS sampling_max,
    -- D-34: la UDF se llama isp_ip_str (ClickHouse no admite '.' en nombres de UDF).
    isp_ip_str(src_ip) AS src_ip_str,
    isp_ip_str(dst_ip) AS dst_ip_str
FROM isp.agg_smtp_sessions;
