-- 63_bl_thresholds.sql [E09]
--
-- T-076 (E09-T04) -- E09 §5.1, §5.2, §5.3 · E00b D-13 · E00e G-1.
--
-- `k`, `offset_log`, `sigma_scale`, piso y su calibración -- ~15 filas
-- (una por (detector_id, metric)), las escribe J6 (deploy/clickhouse/jobs/,
-- fuera de este layout). LIFETIME más corto que el resto (MIN 120 MAX 180,
-- no MIN 240 MAX 360): es la tabla que gobierna directamente cuándo un
-- detector dispara, así que una recalibración tiene que propagarse más
-- rápido que un perfil.

CREATE TABLE IF NOT EXISTS isp.bl_thresholds
(
    detector_id          LowCardinality(String),
    metric               LowCardinality(String),
    k_sigma              Float64,          -- umbral vigente (o h de CUSUM)
    k_sigma_measured     Float64,          -- el que salió del cuantil empírico
    offset_log           Float64,          -- corrección de POSICIÓN, E09 §4.6.6
    offset_log_measured  Float64,          -- el medido antes del clamp por paso
    max_offset_log       Float64,          -- tope POR MÉTRICA (D-12): 1.0 en pps/bps, 5.0 en cardinalidad y flows
    sigma_scale          Float64,          -- corrección de ESCALA, §4.6.6; 1.0 = sin corrección
    sigma_scale_measured Float64,
    floor_value          Float64,          -- espejo del Param del detector, para auditoría
    veto_max_sigma       Float64,
    veto_ceiling         Float64,
    target_fp_per_day    Float64,
    measured_fp_per_day  Float64,
    entities_tested      UInt32,
    residual_samples     UInt64,
    calibration_source   Enum8('default'=0,'empirical'=1,'manual'=2,'clamped'=3),
    calibrated_at        DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(calibrated_at)
ORDER BY (detector_id, metric);

CREATE DICTIONARY IF NOT EXISTS isp.dict_bl_thresholds
(
    detector_id String, metric String,
    k_sigma Float64 DEFAULT 6.0, offset_log Float64 DEFAULT 0,
    sigma_scale Float64 DEFAULT 1.0,          -- E09 §4.6.6, D-12
    veto_max_sigma Float64 DEFAULT 1.0, veto_ceiling Float64 DEFAULT 0
)
PRIMARY KEY detector_id, metric
SOURCE(CLICKHOUSE(QUERY 'SELECT detector_id, metric, k_sigma, offset_log, sigma_scale, veto_max_sigma, veto_ceiling FROM isp.bl_thresholds FINAL'))
LAYOUT(COMPLEX_KEY_HASHED()) LIFETIME(MIN 120 MAX 180);

-- Vista para el panel de calibración de E12 (E09 §5.3): passthrough sobre
-- bl_thresholds FINAL, sin columnas derivadas -- todo lo que hace falta ya
-- está tipado y nombrado.
CREATE OR REPLACE VIEW isp.v_bl_thresholds
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
    detector_id,
    metric,
    k_sigma,
    k_sigma_measured,
    offset_log,
    offset_log_measured,
    max_offset_log,
    sigma_scale,
    sigma_scale_measured,
    floor_value,
    veto_max_sigma,
    veto_ceiling,
    target_fp_per_day,
    measured_fp_per_day,
    entities_tested,
    residual_samples,
    calibration_source,
    calibrated_at
FROM isp.bl_thresholds FINAL;
