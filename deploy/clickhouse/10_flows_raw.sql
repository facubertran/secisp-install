-- 10_flows_raw.sql [E03]
--
-- T-038 (E03-T02) -- E03 §4.2.1, §4.2.2, §4.2.3 · E00 §4.1.2 · E00b D-8 ·
-- E03 §3 D9 · E03 §5.2 (v_flows_raw).
--
-- Tabla de flujo crudo dual-stack. Las columnas, tipos, orden, PARTITION BY,
-- ORDER BY y TTL son EXACTAMENTE los de E00 §4.1.2: E03 solo agrega, de forma
-- aditiva, los codecs (D9), los indices de salto y el SETTINGS. Depende de
-- 00_database.sql (la base isp y sus dos UDFs).

CREATE TABLE IF NOT EXISTS isp.flows_raw
(
    -- == Tiempo ================================================================
    ts_start         DateTime64(3, 'UTC')  CODEC(DoubleDelta, ZSTD(1)),
    ts_end           DateTime64(3, 'UTC')  CODEC(DoubleDelta, ZSTD(1)),
    ts_received      DateTime64(3, 'UTC')  CODEC(DoubleDelta, ZSTD(1)),
    ts_inserted      DateTime64(3, 'UTC')  DEFAULT now64(3) CODEC(DoubleDelta, ZSTD(1)),

    -- == Exportador =============================================================
    exporter_ip      IPv6                  CODEC(ZSTD(1)),
    exporter_id      LowCardinality(String),
    obs_domain_id    UInt32                CODEC(T64, ZSTD(1)),
    in_if            UInt32                CODEC(T64, ZSTD(1)),
    out_if           UInt32                CODEC(T64, ZSTD(1)),
    if_direction     Enum8('unknown' = 0, 'ingress' = 1, 'egress' = 2) CODEC(ZSTD(1)),

    -- == Direcciones y servicio =================================================
    ip_version       UInt8                 CODEC(ZSTD(1)),
    src_ip           IPv6                  CODEC(ZSTD(1)),
    dst_ip           IPv6                  CODEC(ZSTD(1)),
    src_port         UInt16                CODEC(T64, ZSTD(1)),
    dst_port         UInt16                CODEC(T64, ZSTD(1)),
    proto            UInt8                 CODEC(ZSTD(1)),
    tcp_flags        UInt16                CODEC(T64, ZSTD(1)),
    tcp_flags_valid  UInt8                 CODEC(ZSTD(1)),
    icmp_type        UInt8                 CODEC(ZSTD(1)),
    icmp_code        UInt8                 CODEC(ZSTD(1)),
    tos              UInt8                 CODEC(ZSTD(1)),

    -- == Volumen -- YA NORMALIZADO POR SAMPLING (E00 §4.2) =====================
    bytes            UInt64                CODEC(T64, ZSTD(1)),
    packets          UInt64                CODEC(T64, ZSTD(1)),
    flows            UInt32                CODEC(T64, ZSTD(1)),
    sampling_applied UInt32                CODEC(DoubleDelta, ZSTD(1)),
    sampling_source  Enum8('none' = 0, 'inband' = 1, 'registry' = 2, 'default' = 3) CODEC(ZSTD(1)),

    -- == Enriquecimiento hecho por el COLLECTOR (E04) ==========================
    src_scope        Enum8('unknown' = 0, 'customer' = 1, 'infra' = 2, 'external' = 3) CODEC(ZSTD(1)),
    dst_scope        Enum8('unknown' = 0, 'customer' = 1, 'infra' = 2, 'external' = 3) CODEC(ZSTD(1)),
    flow_dir         Enum8('unknown' = 0, 'outbound' = 1, 'inbound' = 2, 'internal' = 3, 'transit' = 4) CODEC(ZSTD(1)),
    customer_id      LowCardinality(String),
    src_asn          UInt32                CODEC(T64, ZSTD(1)),
    dst_asn          UInt32                CODEC(T64, ZSTD(1)),
    src_cc           LowCardinality(String),
    dst_cc           LowCardinality(String),

    -- == Indices de salto (aditivos, propiedad de E03) =========================
    -- dst_ip es 4a en el ORDER BY: la consulta "quien le pego a esta victima"
    -- no tiene prefijo utilizable. El bloom la convierte en lectura de granos.
    INDEX idx_dst_ip      dst_ip      TYPE bloom_filter(0.01) GRANULARITY 4,
    -- customer_id no esta en el ORDER BY: el drill-down del panel filtra por el.
    INDEX idx_customer    customer_id TYPE set(256)           GRANULARITY 8,
    -- diagnostico operativo: "todo lo de este router en esta hora".
    INDEX idx_exporter    exporter_id TYPE set(64)            GRANULARITY 8,
    -- E11 excluye CDN por ASN; E10 agrupa destinos por ASN.
    INDEX idx_dst_asn     dst_asn     TYPE set(1024)          GRANULARITY 8
)
ENGINE = MergeTree
PARTITION BY toStartOfHour(ts_received)
ORDER BY (toStartOfMinute(ts_received), flow_dir, src_ip, dst_ip, proto, dst_port)
TTL toDateTime(ts_received) + INTERVAL 12 HOUR DELETE
SETTINGS index_granularity = 8192,
         ttl_only_drop_parts = 1,
         min_bytes_for_wide_part = 10485760,
         non_replicated_deduplication_window = 1000;

-- Proyeccion 1:1 de flows_raw con src_ip_str/dst_ip_str agregados. Existe
-- para que Grafana y el forense manual no necesiten permiso sobre la tabla
-- base (ADR-016, E03 §5.2).
--
-- SQL SECURITY DEFINER (T-092, E12 §5.7.1/§5.7.2): sin esta cláusula, una
-- vista normal de ClickHouse ejecuta con los privilegios del INVOCADOR
-- sobre las tablas que su SELECT nombra -- no alcanza con el GRANT SELECT
-- sobre la vista misma. Verificado a mano contra un ClickHouse 24.8 real:
-- sin SQL SECURITY DEFINER, secisp_grafana recibe ACCESS_DENIED sobre
-- isp.flows_raw al consultar esta vista, exactamente lo que el comentario
-- de arriba dice que no debería pasar. Sin DEFINER = ... explícito por la
-- misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout.
CREATE VIEW IF NOT EXISTS isp.v_flows_raw
SQL SECURITY DEFINER
AS
SELECT
    *,
    isp_ip_str(src_ip) AS src_ip_str,
    isp_ip_str(dst_ip) AS dst_ip_str
FROM isp.flows_raw;
