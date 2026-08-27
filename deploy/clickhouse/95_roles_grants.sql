-- 95_roles_grants.sql [E12]
--
-- T-092 (E12a-T30) -- E00b D-39 · E12 §5.7, §5.7.1, §5.7.2, §5.7.3 · E00c
-- C-18 · E00e G-3, G-6a · E10 §5.4 · E11 §5.7.
--
-- ARCHIVO GENERADO -- no editar a mano. Lo produce
-- internal/ops/grants.Generate() (`go generate ./internal/ops/grants/...`,
-- ver internal/ops/grants/gen/main.go); test/schema/grants_test.go
-- (TestGeneratedFileMatchesGenerator) falla en CI si este archivo se
-- desvía de lo que el generador produciría hoy. Editar acá se pierde en la
-- próxima corrida de `go generate`.
--
-- Es la ÚNICA declaración de roles y GRANTs del proyecto (E00b D-39): E03
-- §5.7 quedó como referencia y E10 §5.4/E11 §5.7 aportan la enumeración de
-- vistas y la lista de qué necesita cada rol de proceso, que este archivo
-- transcribe.
--
-- Por qué NO hay ni un GRANT con comodín: `GRANT SELECT ON isp.v_* TO secisp_ro`
-- no es SQL válido -- ClickHouse no acepta comodines en el nombre de tabla
-- de un GRANT (solo `db.*`, que es lo contrario de lo que se quiere: incluiría
-- `flows_raw` y las `agg_*`). Escrito así, este archivo abortaba en la primera
-- sentencia y NINGÚN rol quedaba con permisos: Grafana daba ACCESS_DENIED
-- en todos los paneles, el mitigador no leía det_cases y el collector no
-- insertaba (E00f H-1, la misma clase de defecto que tumbó este archivo
-- bajo su nombre viejo varias veces). Por eso se enumera vista por vista, y
-- por eso se GENERA en vez de mantenerse a mano.
--
-- Va DESPUÉS de todo lo que nombra (E03 §4.9.1: el orden por bytes ES el
-- orden de dependencias) y ANTES de 99_ttl_overrides.sql, que no crea
-- ningún objeto nuevo. En particular va DESPUÉS de 94b_profile_panel.sql
-- (E00d F-2): el SETTINGS PROFILE secisp_panel y la QUOTA
-- secisp_panel_quota, sin destinatario, ya existen cuando este archivo
-- corre -- acá se les asigna el rol y el usuario.
--
-- CONTRASEÑAS: las cinco CREATE USER de abajo llevan un placeholder
-- `CHANGE_ME_*` -- NO son secretos reales, y quedan en texto plano en este
-- archivo versionado. Rotarlas es un paso OBLIGATORIO de post-instalación
-- (docs/ops/roles-y-grants.md) antes de exponer ClickHouse más allá de
-- localhost: `ALTER USER <rol> IDENTIFIED WITH sha256_password BY '<secreto>'`.
-- No depende de qué valor haya acá: test/integration/smoke_udf_test.go ya
-- asume exactamente esto (openUserDB pisa la contraseña con ALTER USER
-- antes de conectar).

-- ── secisp_ro: el rol de lectura (E12 §5.7.1) ──────────────────────────────
CREATE ROLE IF NOT EXISTS secisp_ro;

-- (E00e G-6a · E10 §9.1 Q21) La otra mitad de la cuota del panel: 94b_profile_panel.sql
-- la crea SIN destinatario porque el rol todavía no existe a esa altura del layout.
-- Sin esta línea el perfil aplica sus topes por query, pero el límite AGREGADO de 900
-- queries/min no rige, y nadie se entera.
ALTER QUOTA secisp_panel_quota TO secisp_ro;

-- ── 47 vistas isp.v_*, enumeradas por bytes de archivo de origen (E00b D-13) ──
-- Generado por internal/ops/grants.Discover(): TODA vista isp.v_* del layout
-- recibe GRANT SELECT, sin excepción -- incluidas las tres `_flat` (E00b D-10)
-- y las de mitigación: dejar una afuera es el defecto exacto de E00f H-1.
-- desde 10_flows_raw.sql
GRANT SELECT ON isp.v_flows_raw TO secisp_ro;
-- desde 11_v_exporter_status.sql
GRANT SELECT ON isp.v_exporter_status TO secisp_ro;
-- desde 12_ops_ingest_health.sql
GRANT SELECT ON isp.v_ingest_health TO secisp_ro;
-- desde 20_agg_src_10s.sql
GRANT SELECT ON isp.v_agg_src_10s TO secisp_ro;
-- desde 21_agg_src_1m.sql
GRANT SELECT ON isp.v_agg_src_1m TO secisp_ro;
GRANT SELECT ON isp.v_agg_src_1m_flat TO secisp_ro;
-- desde 22_agg_src_1h.sql
GRANT SELECT ON isp.v_agg_src_1h TO secisp_ro;
-- desde 25_agg_src_dst_svc_1m.sql
GRANT SELECT ON isp.v_agg_src_dst_svc_1m TO secisp_ro;
GRANT SELECT ON isp.v_agg_src_dst_svc_1m_flat TO secisp_ro;
-- desde 26_agg_dst_svc_1m.sql
GRANT SELECT ON isp.v_agg_dst_svc_1m TO secisp_ro;
GRANT SELECT ON isp.v_agg_dst_svc_1m_flat TO secisp_ro;
-- desde 27_agg_dst_svc_1h.sql
GRANT SELECT ON isp.v_agg_dst_svc_1h TO secisp_ro;
-- desde 30_agg_src_port_1m.sql
GRANT SELECT ON isp.v_agg_src_port_1m TO secisp_ro;
-- desde 35_agg_smtp_sessions.sql
GRANT SELECT ON isp.v_agg_smtp_sessions TO secisp_ro;
-- desde 38_v_smtp_sessions.sql
GRANT SELECT ON isp.v_smtp_sessions TO secisp_ro;
-- desde 39_v_ops_data_health.sql
GRANT SELECT ON isp.v_ops_data_health TO secisp_ro;
-- desde 40_det.sql
GRANT SELECT ON isp.v_det_events TO secisp_ro;
GRANT SELECT ON isp.v_det_cases TO secisp_ro;
-- desde 43_v_det.sql
GRANT SELECT ON isp.v_det_case_events TO secisp_ro;
GRANT SELECT ON isp.v_det_runs TO secisp_ro;
GRANT SELECT ON isp.v_det_suppressed_1h TO secisp_ro;
GRANT SELECT ON isp.v_det_detectors TO secisp_ro;
-- desde 50_mit.sql
GRANT SELECT ON isp.v_mit_actions TO secisp_ro;
GRANT SELECT ON isp.v_mit_blocks_active TO secisp_ro;
GRANT SELECT ON isp.v_mit_customer_history TO secisp_ro;
GRANT SELECT ON isp.v_mit_quality_30d TO secisp_ro;
-- desde 60_bl_profiles.sql
GRANT SELECT ON isp.v_bl_profiles TO secisp_ro;
-- desde 61_bl_entities.sql
GRANT SELECT ON isp.v_bl_entities TO secisp_ro;
GRANT SELECT ON isp.v_bl_coverage TO secisp_ro;
-- desde 62_bl_residuals.sql
GRANT SELECT ON isp.v_bl_residuals TO secisp_ro;
-- desde 63_bl_thresholds.sql
GRANT SELECT ON isp.v_bl_thresholds TO secisp_ro;
-- desde 70_v_panel.sql
GRANT SELECT ON isp.v_attack_events TO secisp_ro;
GRANT SELECT ON isp.v_attack_victims TO secisp_ro;
GRANT SELECT ON isp.v_attackers_now TO secisp_ro;
GRANT SELECT ON isp.v_attack_pairs_1m TO secisp_ro;
GRANT SELECT ON isp.v_ops_blind TO secisp_ro;
GRANT SELECT ON isp.v_reputation_self TO secisp_ro;
GRANT SELECT ON isp.v_net_prefixes TO secisp_ro;
GRANT SELECT ON isp.v_customer_ips TO secisp_ro;
GRANT SELECT ON isp.v_ops_panel_cost TO secisp_ro;
-- desde 90b_v_config_history.sql
GRANT SELECT ON isp.v_config_history TO secisp_ro;
-- desde 93_ops_exporter_stats.sql
GRANT SELECT ON isp.v_ops_exporters TO secisp_ro;
-- desde 94c_ops_views.sql
GRANT SELECT ON isp.v_ops_o5 TO secisp_ro;
GRANT SELECT ON isp.v_ops_pending_review TO secisp_ro;
GRANT SELECT ON isp.v_ops_health TO secisp_ro;
GRANT SELECT ON isp.v_mit_router_events TO secisp_ro;
GRANT SELECT ON isp.v_ops_panel_quota TO secisp_ro;

-- ── dictGet: derivados de qué diccionario consulta cada vista otorgada arriba,
--    directo o a través de una UDF net_*/isp_*_str/net_label (E10 §5.4 N4) ──────
GRANT dictGet ON isp.dict_asn TO secisp_ro;
GRANT dictGet ON isp.dict_asn_meta TO secisp_ro;
GRANT dictGet ON isp.dict_detector_family TO secisp_ro;
GRANT dictGet ON isp.dict_net_prefixes TO secisp_ro;
GRANT dictGet ON isp.dict_service_names TO secisp_ro;

-- Ningún GRANT sobre isp.flows_raw, isp.agg_*, isp.det_*, isp.mit_*, isp.dim_*,
-- ni sobre isp.bl_*: secisp_ro solo ve por vista.

-- ── system.*: SQL SECURITY DEFINER en la vista, no GRANT a secisp_ro (E12 §5.7.2) ──
-- isp.v_ops_panel_cost (70_v_panel.sql) e isp.v_ops_data_health (39_v_ops_data_health.sql)
-- leen system.query_log/system.parts con SQL SECURITY DEFINER, resuelto a CURRENT_USER
-- al CREATE (quien corre `secisp schema apply` tiene ACCESS MANAGEMENT). No hay ningún
-- GRANT ... ON system.* a secisp_ro ni a secisp_grafana acá, a propósito: system.query_log
-- guarda el texto completo de las queries, que en este sistema incluye IPs de clientes.

-- ── secisp_collector: E01/E02, el único escritor de la capa de flujo (E03 §5.7) ──
CREATE USER IF NOT EXISTS secisp_collector IDENTIFIED WITH sha256_password BY 'CHANGE_ME_secisp_collector_password';
GRANT INSERT ON isp.flows_raw TO secisp_collector;
GRANT SELECT ON isp.flows_raw TO secisp_collector;
GRANT SELECT ON isp.agg_smtp_sessions TO secisp_collector;
GRANT INSERT ON isp.ops_ingest_health TO secisp_collector;
GRANT SELECT ON isp.ops_schema_version TO secisp_collector;
GRANT SELECT ON isp.dim_exporters TO secisp_collector;
GRANT SELECT ON isp.dim_net_prefixes TO secisp_collector;
GRANT SELECT ON isp.dim_exporter_ifaces TO secisp_collector;
GRANT SELECT ON isp.dim_reputation TO secisp_collector;
GRANT SELECT ON isp.dim_customer_ips TO secisp_collector;
GRANT dictGet ON isp.dict_net_prefixes TO secisp_collector;
GRANT dictGet ON isp.dict_asn TO secisp_collector;
GRANT SELECT ON system.parts TO secisp_collector;
-- SÍ tiene SELECT sobre isp.flows_raw e isp.agg_smtp_sessions -- no para
-- releer lo que escribe, sino porque las MATERIALIZED VIEW que cuelgan de
-- esas dos tablas ejecutan con los privilegios de quien originó el INSERT
-- (ver el comentario de collectorGrants() en internal/ops/grants/render.go).

-- ── secisp_engine: motor de detección (E05–E09) ─────────────────────────────
CREATE USER IF NOT EXISTS secisp_engine IDENTIFIED WITH sha256_password BY 'CHANGE_ME_secisp_engine_password';
GRANT SELECT ON isp.* TO secisp_engine;
GRANT INSERT ON isp.det_events TO secisp_engine;
GRANT INSERT ON isp.det_cases TO secisp_engine;
GRANT INSERT ON isp.ops_detect_state TO secisp_engine;
GRANT INSERT ON isp.ops_audit TO secisp_engine;
GRANT INSERT ON isp.bl_profiles TO secisp_engine;
GRANT INSERT ON isp.agg_src_1h TO secisp_engine;
GRANT INSERT ON isp.agg_dst_svc_1h TO secisp_engine;
GRANT dictGet ON isp.dict_net_prefixes TO secisp_engine;
GRANT dictGet ON isp.dict_asn TO secisp_engine;
GRANT dictGet ON isp.dict_asn_meta TO secisp_engine;
GRANT dictGet ON isp.dict_detector_family TO secisp_engine;
GRANT dictGet ON isp.dict_service_names TO secisp_engine;
GRANT dictGet ON isp.dict_bl_calendar TO secisp_engine;
GRANT dictGet ON isp.dict_bl_profile TO secisp_engine;
GRANT dictGet ON isp.dict_bl_entity TO secisp_engine;
GRANT dictGet ON isp.dict_bl_thresholds TO secisp_engine;
GRANT dictGet ON isp.dict_bl_service_seen TO secisp_engine;
GRANT INSERT ON isp.dim_detectors TO secisp_engine;

-- ── secisp_mitigator: E11 ────────────────────────────────────────────────────
CREATE USER IF NOT EXISTS secisp_mitigator IDENTIFIED WITH sha256_password BY 'CHANGE_ME_secisp_mitigator_password';
GRANT SELECT ON isp.ops_schema_version TO secisp_mitigator;
GRANT SELECT ON isp.dim_detectors TO secisp_mitigator;
GRANT SELECT ON isp.det_cases TO secisp_mitigator;
GRANT SELECT ON isp.det_events TO secisp_mitigator;
GRANT SELECT ON isp.det_suppress_rules TO secisp_mitigator;
GRANT SELECT ON isp.dim_net_prefixes TO secisp_mitigator;
GRANT SELECT ON isp.dim_customer_ips TO secisp_mitigator;
GRANT SELECT ON isp.dim_services TO secisp_mitigator;
GRANT SELECT ON isp.dim_amp_ports TO secisp_mitigator;
GRANT SELECT ON isp.dim_reputation TO secisp_mitigator;
GRANT SELECT ON isp.dim_exporters TO secisp_mitigator;
GRANT SELECT ON isp.dim_exporter_ifaces TO secisp_mitigator;
GRANT SELECT ON isp.mit_actions TO secisp_mitigator;
GRANT INSERT ON isp.mit_actions TO secisp_mitigator;
GRANT INSERT ON isp.ops_audit TO secisp_mitigator;
GRANT dictGet ON isp.dict_net_prefixes TO secisp_mitigator;
GRANT dictGet ON isp.dict_asn TO secisp_mitigator;
GRANT dictGet ON isp.dict_service_names TO secisp_mitigator;

-- ── secisp_ops: watchdog + CLI de operación (E12) ────────────────────────────
CREATE USER IF NOT EXISTS secisp_ops IDENTIFIED WITH sha256_password BY 'CHANGE_ME_secisp_ops_password';
GRANT secisp_ro TO secisp_ops;
GRANT SELECT ON system.tables TO secisp_ops;
GRANT SELECT ON system.parts TO secisp_ops;
GRANT SELECT ON system.dictionaries TO secisp_ops;
GRANT SELECT ON system.mutations TO secisp_ops;
GRANT SELECT ON system.query_log TO secisp_ops;
GRANT SELECT ON system.errors TO secisp_ops;
GRANT SELECT ON system.metrics TO secisp_ops;
GRANT SELECT ON system.asynchronous_metrics TO secisp_ops;
GRANT SELECT ON isp.ops_schema_version TO secisp_ops;
GRANT SELECT ON isp.dim_net_prefixes TO secisp_ops;
GRANT INSERT ON isp.ops_watchdog_checks TO secisp_ops;
GRANT INSERT ON isp.ops_exporter_stats TO secisp_ops;
GRANT INSERT ON isp.ops_feedback TO secisp_ops;
GRANT INSERT ON isp.ops_audit TO secisp_ops;
-- Toda su lectura del esquema isp entra por secisp_ro; lo propio es system.* y los cuatro INSERT ops_*.

-- ── secisp_config: CLI declarativo de E04 §4.11, lo corre una PERSONA ────────
-- Séptimo usuario, desviación declarada de E00b D-39 (que enumera seis nombres,
-- todos de PROCESO). Es la identidad de `secisp config diff|export|apply`: el
-- único con INSERT sobre las tres dim_* declarativas. NO se le dio a secisp_ops
-- porque ese es el usuario del daemon watchdog, e INSERT sobre dim_net_prefixes
-- es un privilegio de bypass de mitigación (scope='infra'/ignore_src exime a una
-- IP de todo bloqueo en ≤60 s, vía el never-block set y las UDF net_ignored_*).
CREATE USER IF NOT EXISTS secisp_config IDENTIFIED WITH sha256_password BY 'CHANGE_ME_secisp_config_password';
GRANT SELECT, INSERT ON isp.dim_net_prefixes TO secisp_config;
GRANT SELECT, INSERT ON isp.dim_exporters TO secisp_config;
GRANT SELECT, INSERT ON isp.dim_exporter_ifaces TO secisp_config;
GRANT INSERT ON isp.ops_audit TO secisp_config;
-- SYSTEM RELOAD DICTIONARY: `config apply` recarga los cuatro diccionarios al
-- terminar (configApplyDicts, cmd/secisp/config_apply.go). ClickHouse no acepta
-- ese privilegio acotado por objeto en todas las versiones, así que va sobre *.*
-- -- es el único GRANT no acotado del archivo, y solo habilita recargar
-- diccionarios, nunca leer ni escribir datos.
GRANT SYSTEM RELOAD DICTIONARY ON *.* TO secisp_config;

-- ── secisp_grafana: SOLO vistas, vía el rol (E00 ADR-016) ───────────────────
-- (E00c C-18) Cero settings propios: los topes viven en el SETTINGS PROFILE de
-- 94b_profile_panel.sql. Redeclararlos acá hace fallar el CREATE USER con
-- SETTING_CONSTRAINT_VIOLATION contra los CONST del perfil.
CREATE USER IF NOT EXISTS secisp_grafana IDENTIFIED WITH sha256_password BY 'CHANGE_ME_secisp_grafana_password'
  SETTINGS PROFILE secisp_panel;
GRANT secisp_ro TO secisp_grafana;
-- Ningún GRANT directo: todo lo que ve entra por el rol enumerado arriba.
-- (isp.v_ops_panel_quota, T-224/94c_ops_views.sql, es la forma en que
-- secisp_grafana ve system.quotas_usage sin un GRANT directo a system.*: ya
-- recibió su GRANT SELECT como cualquier otra vista isp.v_*, en la sección
-- de vistas de más arriba -- Discover() la encuentra sola.)
