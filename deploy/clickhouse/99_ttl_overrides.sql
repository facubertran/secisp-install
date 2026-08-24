-- 99_ttl_overrides.sql [E03]
--
-- T-057 (E03-T14) -- E03 §3 D8, §4.8.4, §5.5 · E00 §4.5.3.
--
-- Los TTL son PALANCAS DEL INSTALADOR, no constantes del DDL (D8): cada
-- CREATE TABLE trae un TTL "de fábrica" (el de referencia de su propia
-- sección), y este archivo lo deja en el número que P10 elige para la
-- instalación real, vía `ALTER TABLE ... MODIFY TTL ...
-- SETTINGS materialize_ttl_after_modify = 0` -- sin rebuild y sin pausa.
--
-- Los nueve parámetros son en SEGUNDOS (UInt32), con el mismo nombre que
-- internal/config.SchemaConfig.TTLParams() expone; internal/config/schema_test.go
-- verifica que los dos conjuntos de nombres coincidan exactamente. `secisp
-- schema apply` (T-059) los liga a los valores resueltos de SEC_SCHEMA_TTL_*
-- (flag > env > config.yaml > default) antes de ejecutar este archivo.
--
-- Va DESPUÉS de los nueve archivos cuyo TTL modifica (10, 20, 21, 22, 25, 26,
-- 27, 30, 35): un ALTER TABLE sobre una tabla que todavía no existe aborta.

ALTER TABLE isp.flows_raw
    MODIFY TTL toDateTime(ts_received) + INTERVAL {ttl_flows_raw_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE isp.agg_src_10s
    MODIFY TTL window_start + INTERVAL {ttl_agg_src_10s_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE isp.agg_src_1m
    MODIFY TTL window_start + INTERVAL {ttl_agg_src_1m_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE isp.agg_src_1h
    MODIFY TTL window_start + INTERVAL {ttl_agg_src_1h_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE isp.agg_src_dst_svc_1m
    MODIFY TTL window_start + INTERVAL {ttl_agg_src_dst_svc_1m_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE isp.agg_dst_svc_1m
    MODIFY TTL window_start + INTERVAL {ttl_agg_dst_svc_1m_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;

-- Piso duro de 7 días (E08 §5.1 R6): internal/config.SchemaConfig.Validate()
-- rechaza un valor por debajo de ese piso ANTES de que `schema apply` llegue
-- a ejecutar esta sentencia.
ALTER TABLE isp.agg_dst_svc_1h
    MODIFY TTL window_start + INTERVAL {ttl_agg_dst_svc_1h_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE isp.agg_src_port_1m
    MODIFY TTL window_start + INTERVAL {ttl_agg_src_port_1m_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;

ALTER TABLE isp.agg_smtp_sessions
    MODIFY TTL window_start + INTERVAL {ttl_agg_smtp_sessions_seconds:UInt32} SECOND DELETE
    SETTINGS materialize_ttl_after_modify = 0;
