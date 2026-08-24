-- 65_bl_service_1h.sql [E09]
--
-- T-076 (E09-T04) -- E09 §5.1 · E00b D-13 · E00e G-1.
--
-- Volumen del ISP entero por servicio y hora: la serie que perfila
-- `anomaly.service_wave` (E09 §4.11.5). La escribe J8 (deploy/clickhouse/
-- jobs/bl_service_1h.sql, fuera de este layout). Sin diccionario y sin
-- vista propia: E09 §5.1 no le asigna ninguno de los cinco de cada ("También
-- crea: --") y §5.3 no la lista entre las cinco vistas del contrato.

CREATE TABLE IF NOT EXISTS isp.bl_service_1h
(
    window_start  DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
    proto         UInt8,
    dst_port      UInt16,
    packets       UInt64,
    bytes         UInt64,
    flows         UInt64,
    uniq_src_entities UInt64,
    uniq_dst_ips  UInt64,
    pps_p95       Float32,
    pps_max       Float32,
    sampling_max  UInt32,
    rolled_at     DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(rolled_at)
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, proto, dst_port)
TTL window_start + INTERVAL 400 DAY DELETE;
