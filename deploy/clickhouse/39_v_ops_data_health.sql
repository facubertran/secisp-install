-- 39_v_ops_data_health.sql [E03]
--
-- T-056 (E03-T13) -- E03 §4.10, §4.8.4 · E00f H-1, H-3b · E03 §5.2, §5.6 ·
-- E03 §6 E03-15, E03-17.
--
-- Vista de salud de la capa de datos. La consumen v_ops_blind (70_v_panel.sql)
-- y v_ops_health (94c_ops_views.sql) de E10/E12, y el watchdog de E12. Va
-- DESPUÉS de todos los agregados que lee (10, 21, 22, 25, 27) y ANTES de
-- 70_v_panel.sql (E00f H-1: un CREATE VIEW sobre un objeto de número mayor
-- aborta el archivo).
--
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2): esta vista lee `system.parts`, y
-- `secisp_ro`/`secisp_grafana` no reciben GRANT sobre `system.*` (mismo
-- criterio que isp.v_ops_panel_cost en 70_v_panel.sql). Sin esta cláusula,
-- `secisp_grafana` pega ACCESS_DENIED en cuanto consulta isp.v_ops_blind
-- (que lee esta vista) — el gap quedó señalado, sin corregir, en el
-- comentario de cabecera de isp.v_ops_blind (70_v_panel.sql, T-083) a la
-- espera de esta task. Sin `DEFINER = …` explícito por la misma razón que
-- v_ops_panel_cost: `secisp_ops` todavía no existe a esta altura del layout
-- (lo crea 95_roles_grants.sql, T-092) y nombrarlo aquí abortaría el
-- archivo entero.

CREATE OR REPLACE VIEW isp.v_ops_data_health
SQL SECURITY DEFINER
AS
SELECT
    (SELECT max(ts_received) FROM isp.flows_raw)                       AS last_flow_ts,
    dateDiff('second', (SELECT max(ts_received) FROM isp.flows_raw), now())
                                                                       AS ingest_lag_seconds,
    (SELECT max(window_start) FROM isp.agg_src_1m)                     AS last_agg_src_1m,
    (SELECT max(window_start) FROM isp.agg_src_dst_svc_1m)             AS last_pair_1m,
    -- Roll-ups horarios (§4.5.3). Si se atrasan más de 2 h, E09 pierde baseline
    -- y la guarda de prevalencia de E08 §4.7 envejece.
    (SELECT max(window_start) FROM isp.agg_src_1h)                     AS last_agg_src_1h,
    (SELECT max(window_start) FROM isp.agg_dst_svc_1h)                 AS last_dst_svc_1h,
    -- D-5: si esto es 0 con clientes activos, la MV está filtrando de más.
    (SELECT count() FROM isp.agg_src_1m
       WHERE window_start >= now() - INTERVAL 5 MINUTE
         AND flow_dir = 'internal')                                    AS internal_rows_5m,
    (SELECT count() FROM isp.flows_raw
       WHERE ts_received >= now() - INTERVAL 5 MINUTE
         AND flow_dir = 'transit')                                     AS transit_flows_5m,
    (SELECT count() FROM isp.flows_raw
       WHERE ts_received >= now() - INTERVAL 5 MINUTE
         AND src_scope = 'unknown')                                    AS unknown_scope_5m,
    (SELECT count() FROM isp.flows_raw
       WHERE ts_received >= now() - INTERVAL 5 MINUTE
         AND flow_dir = 'outbound' AND tcp_flags_valid = 1)            AS flags_flows_5m,
    (SELECT sum(bytes_on_disk) FROM system.parts
       WHERE database = 'isp' AND active)                              AS bytes_on_disk,
    (SELECT count() FROM system.parts
       WHERE database = 'isp' AND active)                              AS active_parts;
