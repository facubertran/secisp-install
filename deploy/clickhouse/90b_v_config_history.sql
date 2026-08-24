-- 90b_v_config_history.sql [E04]
--
-- T-089 (E04-T12) -- E04 §4.10 · E00b D-36 · E00f H-1 · E12 §5.4 · E04-09.
--
-- "¿Quién sacó esta red de las exclusiones y cuándo?" se contesta con una
-- query sobre esta vista, sin tocar isp.ops_audit a mano.
--
-- Número `90b`, no un número propio de E04, y va DESPUÉS de
-- `90_ops_audit.sql` [E12] -- que crea la tabla que esta vista lee -- y
-- ANTES de `95_roles_grants.sql`, que hace
-- `GRANT SELECT ON isp.v_config_history TO secisp_ro`. ClickHouse resuelve
-- el cuerpo del CREATE VIEW al crearla: un número menor que `90_` fallaría
-- con UNKNOWN_TABLE porque isp.ops_audit no existiría todavía, y un GRANT
-- sobre esta vista si no existiera abortaría el archivo de roles entero
-- (E00f H-1) dejando el sistema sin ningún usuario. El bloque numérico es
-- el de E12 por esa dependencia y nada más; la épica dueña del contenido
-- sigue siendo E04 (§7 bis de la secuencia de desarrollo).
--
-- isp.ops_audit es MergeTree, no ReplacingMergeTree (D-36): dos cambios
-- idénticos sobre el mismo object_key en instantes distintos son DOS
-- HECHOS, y esta vista no puede asumir deduplicación alguna -- lee todas
-- las filas de ops_audit tal cual están, sin FINAL ni argMax.
--
-- before/after son JSON libre, no columnas tipadas: `ignore_dst` e
-- `is_enabled` se extraen con JSONExtractUInt. Si antes/after no contienen
-- esas claves (p.ej. un object_type que no es dim_net_prefixes),
-- JSONExtractUInt devuelve 0 -- no lanza. Si E12 cambia antes/after a otra
-- forma, esta vista deja de significar lo mismo (Trampa de T-089).

CREATE OR REPLACE VIEW isp.v_config_history
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
    ts, actor, actor_source, host, object_type, object_key, op, reason, config_version,
    JSONExtractUInt(before, 'ignore_dst') AS ignore_dst_antes,
    JSONExtractUInt(after,  'ignore_dst') AS ignore_dst_despues,
    JSONExtractUInt(before, 'is_enabled') AS habilitado_antes,
    JSONExtractUInt(after,  'is_enabled') AS habilitado_despues
FROM isp.ops_audit
ORDER BY ts DESC;
