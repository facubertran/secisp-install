-- 11_v_exporter_status.sql [E04]
--
-- T-067 (E04-T11) -- E04 §4.6.2 · E00b D-17 · E00b D-34 · E00b D-37 ·
-- E00f H-1 · E04-11 · E04-12 · E04-23.
--
-- Estado declarado vs. observado por exportador: el operador y el panel de
-- E10 ven, por router, si está registrado, si dejó de reportar y si lo que
-- exporta coincide con lo que declaró (P3/P4, respondidas por E00 §9 pero
-- que caducan con cualquier upgrade de RouterOS -- esta vista es la que las
-- vuelve a medir todos los días).
--
-- NÚMERO -- H-1, bloqueante de arranque. Por su tabla declarada
-- (dim_exporters, 0A_) esta vista caería en el bloque 0x -- por ejemplo
-- '0B_', el nombre que H-1 propone literalmente -- pero el lado OBSERVADO
-- de abajo hace GROUP BY sobre isp.flows_raw, que se crea en
-- 10_flows_raw.sql [E03]. ClickHouse resuelve el cuerpo de una vista al
-- crearla: '0B_' < '10_' por el solo orden lexicográfico (por BYTES, D-13;
-- un `sort` con locale no vale), así que el CREATE VIEW referenciaría una
-- tabla inexistente, abortaría, y con él se caería `10_flows_raw.sql` y
-- absolutamente todo lo que sigue en el instalador -- instalación entera
-- perdida, peor que el defecto que H-1 corrige. '11_' cumple las tres
-- condiciones que importan: después de '0A_' (dim_exporters), después de
-- '10_' (flows_raw), y antes de '70_v_panel.sql' (E10 §5.1 crea
-- v_ops_blind sobre esta vista) y de '95_roles_grants.sql' (E12 §5.7.1
-- hace GRANT SELECT sobre ella) -- un CREATE VIEW o un GRANT contra un
-- objeto de número mayor aborta su archivo entero, y en el caso de
-- '95_' eso se lleva puestos todos los usuarios del sistema.
--
-- D-17 -- exporter_id nunca es la cadena vacía. Un router no registrado
-- aparece del lado OBSERVADO con exporter_id = 'ip:' + <IP de origen del
-- datagrama>. Con '' en cambio, el GROUP BY colapsaría TODOS los routers
-- desconocidos en una sola fila: el panel diría "1 exportador
-- desconocido" cuando hay tres, y ninguna alerta podría distinguirlos
-- (E04-23: 3 IPs no declaradas -> 3 filas, nunca una).
--
-- D-34 -- se usa isp_ip_str(...), nunca ip_str( ni isp.ip_str(.
--
-- D-37 -- la métrica que declara "el collector deja de recibir de este
-- exportador" es sec_collector_last_seen_timestamp_seconds{exporter_id},
-- que emite E01 §5.3. Esta vista NO la referencia (es una métrica de
-- Prometheus, no una columna de ClickHouse) pero el nombre es el mismo que
-- usa E12 para alertar 'stale': no inventar sec_collector_last_packet_...,
-- que no existe y haría que la alerta nunca disparara.

CREATE OR REPLACE VIEW isp.v_exporter_status
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
WITH
-- Lado DECLARADO: una fila por exporter_id, con sus N direcciones
-- colapsadas. El colapso hace falta porque dim_exporters tiene una fila
-- por (exporter_ip, obs_domain_id) y sin él un router con loopback +
-- interfaz física aparecería dos veces.
declarado AS
(
    SELECT
        exporter_id,
        arrayStringConcat(arraySort(groupUniqArray(isp_ip_str(exporter_ip))), ',') AS exporter_ips,
        any(hostname)             AS hostname,
        any(role)                 AS role,
        max(sampling_override)    AS sampling_override,
        max(expect_tcp_flags)     AS expect_tcp_flags,
        max(expect_ipv6)          AS expect_ipv6,
        max(expect_if_direction)  AS expect_if_direction,
        1                         AS registrado
    FROM isp.dim_exporters FINAL
    WHERE is_enabled = 1
    GROUP BY exporter_id
),
-- Lado OBSERVADO: lo que realmente llegó en la última hora. Incluye los
-- NO registrados, que llegan con exporter_id = 'ip:<IP>' (D-17) -- uno por
-- router, no todos juntos.
observado AS
(
    SELECT
        exporter_id,
        max(ts_received)                AS last_seen,
        sum(flows)                       AS flows_1h,
        max(sampling_applied)            AS sampling_seen,
        anyLast(sampling_source)         AS sampling_source_seen,
        avg(tcp_flags_valid)             AS tcp_flags_ratio,
        avg(ip_version = 6)              AS ipv6_ratio,
        avg(in_if != 0 OR out_if != 0)   AS if_known_ratio
    FROM isp.flows_raw
    WHERE ts_received >= now() - INTERVAL 1 HOUR
    GROUP BY exporter_id
)
SELECT
    -- ON explícito, NUNCA USING: en un FULL JOIN de ClickHouse la columna
    -- de USING se resuelve por el lado izquierdo, así que las filas que
    -- solo existen a la derecha (los no registrados) saldrían con
    -- exporter_id = '' -- exactamente el bug que D-17 viene a resolver.
    -- Con ON, las dos columnas (d.exporter_id y o.exporter_id) quedan
    -- disponibles y el `if` de abajo elige la que corresponde.
    if(d.exporter_id != '', d.exporter_id, o.exporter_id)   AS exporter_id,
    -- Para un no registrado, la "IP declarada" es la que ya viaja adentro
    -- del propio id ('ip:203.0.113.1' -> '203.0.113.1').
    if(d.exporter_id != '', d.exporter_ips,
       substring(o.exporter_id, 4))                         AS exporter_ips,
    d.hostname                                              AS hostname,
    d.role                                                  AS role,
    d.sampling_override                                     AS sampling_override,
    -- 1 = está en dim_exporters; 0 = llegó tráfico de un router desconocido.
    -- Equivale a startsWith(exporter_id, 'ip:'); se expone como columna
    -- para que E10 no tenga que parsear la etiqueta en el panel.
    d.registrado                                            AS registrado,
    o.last_seen                                             AS last_seen,
    dateDiff('second', o.last_seen, now())                  AS stale_seconds,
    o.flows_1h                                              AS flows_1h,
    o.sampling_seen                                         AS sampling_seen,
    o.sampling_source_seen                                  AS sampling_source_seen,
    -- Deriva entre lo declarado y lo observado. Responde P3/P4 con datos,
    -- todos los días, en vez de con la declaración de E00 §9.
    d.expect_tcp_flags                                      AS expect_tcp_flags,
    o.tcp_flags_ratio                                       AS tcp_flags_ratio,
    d.expect_ipv6                                           AS expect_ipv6,
    o.ipv6_ratio                                            AS ipv6_ratio,
    d.expect_if_direction                                   AS expect_if_direction,
    o.if_known_ratio                                        AS if_known_ratio,
    multiIf(d.registrado = 0,                                    'unregistered',
            o.last_seen = toDateTime64(0, 3, 'UTC'),             'never',
            dateDiff('second', o.last_seen, now()) > 300,        'stale',
                                                                  'ok') AS status
FROM declarado AS d
FULL OUTER JOIN observado AS o ON d.exporter_id = o.exporter_id
SETTINGS join_use_nulls = 0;
