-- 12_ops_ingest_health.sql [E02]
--
-- T-068 (E02-T16) -- E02 §5.3, §5.3.1, §5.3.2 · E00b D-13, D-26 · E00c C-3,
-- C-20 · E00f H-3, deuda 1.
--
-- Requiere enmienda a E00 §2.3 ("collector escribe solo flows_raw"): esta es
-- la ÚNICA tabla operativa adicional que escribe el collector (E02 §5.3, A2).
-- 1 fila por minuto por instancia = 1440 filas/día, volumen despreciable.
--
-- Para qué: es la única forma de que el motor de detección (E05) sepa que la
-- ventana que está evaluando tuvo la ingesta degradada. Qué NO es: NO es un
-- interruptor de "esta ventana no vale" -- gradúa la confianza, no descarta
-- hallazgos (C-3 enmienda D-26, ver isp.v_ingest_health y las dos consultas
-- de internal/sink/queries.go).
--
-- Reubicada a 12_ (en vez de un número en el bloque 9x) por C-20/H-1: su
-- vista v_ingest_health no debe referenciar ningún objeto isp.* creado en un
-- archivo de número mayor -- acá no hace falta ninguno, la tabla se basta a
-- sí misma. Número reservado por E03-T16 (T-069); el contenido es de E02.

CREATE TABLE IF NOT EXISTS isp.ops_ingest_health
(
    minute            DateTime('UTC'),
    instance          LowCardinality(String),
    written_at        DateTime64(3, 'UTC'),

    -- Contadores del minuto (delta, no acumulado).
    rows_offered      UInt64,   -- lo que E01 entregó a AppendChunk
    rows_batched      UInt64,   -- lo que entró al batch (offered - shed)
    rows_inserted     UInt64,   -- lo que ClickHouse confirmó
    rows_shed         UInt64,   -- descartado por shedding (E02 §3.9)
    shed_p1           UInt64,
    shed_p2           UInt64,
    shed_p3           UInt64,

    batches_ok        UInt32,
    batches_retried   UInt32,
    batches_to_wal    UInt32,
    batches_replayed  UInt32,
    batches_dropped   UInt32,   -- capacity + expired + corrupt
    batches_poison    UInt32,

    wal_bytes         UInt64,
    wal_segments      UInt16,
    wal_oldest_age_s  UInt32,

    clickhouse_up     UInt8,
    circuit_state     UInt8,    -- 0=closed 1=half_open 2=open
    sink_paused       UInt8,
    shed_level        UInt8,    -- 4=sin shedding, 3/2/1 = escalón activo
    parts_active      UInt32,

    flush_p50_ms      UInt32,
    flush_p99_ms      UInt32,

    -- Rango temporal REPUESTO por el replayer durante este minuto (D-30).
    -- Es [min(ts_received), max(ts_received)] sobre todos los batches que el
    -- replayer insertó con éxito en el minuto. Con batches_replayed = 0 los
    -- dos quedan en el centinela toDateTime64(0, 3, 'UTC') y E05 los ignora
    -- (E02 §5.3.2, §4.7, §3.13). DateTime64(3,'UTC') y NO DateTime('UTC'):
    -- el rango se mide sobre ts_received de flows_raw, que es DateTime64(3);
    -- truncar a segundos podría hacer que E05 se saltee la última ventana de
    -- menos de un segundo del drenado (C-20).
    replayed_ts_min   DateTime64(3, 'UTC'),
    replayed_ts_max   DateTime64(3, 'UTC'),

    -- 1 si el minuto NO es confiable para detección:
    --   rows_shed > 0  OR  batches_dropped > 0  OR  batches_poison > 0
    -- La AUSENCIA de fila (ClickHouse caído durante ese minuto, E02 §5.3.3)
    -- se trata igual: degraded = 1 con shed_ratio desconocido, nunca
    -- degraded = 0. En ningún caso descarta hallazgos (C-3): solo penaliza
    -- confidence, ver internal/sink/queries.go.
    degraded          UInt8
)
ENGINE = ReplacingMergeTree(written_at)
PARTITION BY toYYYYMM(minute)
ORDER BY (minute, instance)
TTL minute + INTERVAL 90 DAY DELETE;

-- Vista de lectura (E05, E10, E12; Grafana solo ve v_* por ADR-016).
-- Sin prefijo ops_ en el nombre de la vista (C-20): v_ingest_health, no
-- v_ops_ingest_health.
CREATE OR REPLACE VIEW isp.v_ingest_health
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
SELECT * FROM isp.ops_ingest_health FINAL;
