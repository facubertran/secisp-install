-- 62_bl_residuals.sql [E09]
--
-- T-076 (E09-T04) -- E09 §5.1, §5.3 · E00b D-13 · E00e G-1 · E00f H-2 §9.7
-- N25.
--
-- Serie de `z` por entidad y ventana de 5 minutos (ANCHA: una columna por
-- métrica, E09 §4.8.4). La escribe J5, que NO vive en este layout (va en
-- deploy/clickhouse/jobs/bl_residuals.sql, cargado por `engine` con
-- go:embed). Solo la vista de lectura es de este archivo.
--
-- top_src_ip (E00f H-2 §9.7 N25): columna agregada a las de E09 §5.1 por
-- decisión explícita de esta task. `anomaly.level_shift` (E09 §4.11.3)
-- proyecta `s.top_src_ip AS src_ip` leyendo esta tabla, pero el bloque
-- literal de §5.1 no la declaraba -- N25 lo dejó anotado como "transcripción
-- pendiente, no una decisión": el valor ya se calcula en la observación de
-- §4.11.1 (`argMax(src_ip, pps_min) AS top_src_ip`, la misma resolveEntity
-- que usan J2/J5/el detector) y J7/§4.11.5 repiten el mismo patrón; lo único
-- que faltaba era la columna para que J5 la escriba. Es la IP dominante de
-- la ventana para TODO entity_kind, incluido customer/src_prefix: E11
-- necesita un /32 sobre el que accionar y no una clave agregada.
CREATE TABLE IF NOT EXISTS isp.bl_residuals
(
    window_start        DateTime('UTC')  CODEC(DoubleDelta, ZSTD(1)),
    entity_kind         Enum8('global'=0,'cohort'=1,'customer'=2,'src_ip'=3,'src_prefix'=4,'service'=5),
    entity_key          String           CODEC(ZSTD(1)),
    slot                UInt8,
    level_used          Enum8('none'=0,'entity'=1,'cohort'=2,'global'=3),
    top_src_ip          IPv6             CODEC(ZSTD(1)),
    z_pps               Float32,
    z_bps               Float32,
    z_uniq_dst_ips      Float32,
    z_uniq_dst_ports    Float32,
    z_flows             Float32,
    obs_pps             Float64,
    obs_bps             Float64,
    obs_uniq_dst_ips    UInt64,
    obs_uniq_dst_ports  UInt64,
    obs_flows           UInt64,
    exp_pps             Float64,
    exp_bps             Float64,
    exp_uniq_dst_ips    Float64,
    exp_uniq_dst_ports  Float64,
    exp_flows           Float64,
    quality             Float32,
    sampling_max        UInt32,
    minutes_seen        UInt8
)
ENGINE = MergeTree
PARTITION BY toDate(window_start)
ORDER BY (entity_kind, entity_key, window_start)
TTL window_start + INTERVAL 14 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- bl_residuals no es ReplacingMergeTree (es la serie cruda de J5): no lleva
-- FINAL. Vista de lectura del panel ("qué tan raro está", E09 §5.3): agrega
-- entity_key explícito (ya viene en la tabla, se repite acá para que la
-- vista sea autocontenida sin depender de que el consumidor sepa el DDL
-- base), el string legible de top_src_ip y z_max = greatest(...) de las
-- cinco métricas.
CREATE OR REPLACE VIEW isp.v_bl_residuals
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
    window_start,
    entity_kind,
    entity_key,
    slot,
    level_used,
    top_src_ip,
    isp_ip_str(top_src_ip)                                              AS top_src_ip_str,
    z_pps, z_bps, z_uniq_dst_ips, z_uniq_dst_ports, z_flows,
    greatest(z_pps, z_bps, z_uniq_dst_ips, z_uniq_dst_ports, z_flows)    AS z_max,
    obs_pps, obs_bps, obs_uniq_dst_ips, obs_uniq_dst_ports, obs_flows,
    exp_pps, exp_bps, exp_uniq_dst_ips, exp_uniq_dst_ports, exp_flows,
    quality,
    sampling_max,
    minutes_seen
FROM isp.bl_residuals;
