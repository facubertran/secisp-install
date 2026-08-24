-- 94_ops_feedback.sql [E12]
--
-- T-087 (E12a-T27) -- E12 §5.3 · E12 §3 D9 · E00b D-28 · E03 §4.9.1.
--
-- El veredicto humano sobre un caso o un evento (D9): true_positive |
-- false_positive | unclear, con quién, cuándo y por qué. La CLI es
-- `secisp case label`. O5 (E00 §1.2l) se calcula con isp.v_ops_o5
-- (94c_ops_views.sql) EXCLUSIVAMENTE desde esta tabla cruzada con
-- isp.mit_actions -- sin un lugar donde un humano diga "esto estuvo mal",
-- O5 no es medible.
--
-- Es tabla aparte y no una columna de det_cases por dos motivos (D9): hay
-- que poder etiquetar eventos SUPRIMIDOS, que no tienen caso y son la
-- materia prima de la calibración (E00 §4.4); y hay que poder corregir un
-- veredicto sin mutar una tabla que escribe el motor.
--
-- La escribe SOLO E12 (vía `secisp case label`, source='cli'; 'ui' e
-- 'import' quedan reservados para cuando exista un frontend o una carga
-- masiva). La leen E05 (para no reabrir un caso etiquetado FP en la misma
-- ventana), E09 (los FP son ejemplos negativos del baselining), E10 (panel
-- de calidad) y E12.
--
-- Relación con D-28: esta tabla registra el VEREDICTO ("esto estuvo mal"),
-- no la SUPRESIÓN futura de ruido igual. Si `verdict='false_positive'`
-- amerita silenciar el patrón, el operador crea además una fila en
-- isp.det_suppress_rules con `rule_name='falso_positivo_confirmado'` (D-28,
-- que unificó los motivos operativos de supresión en esa única tabla) --
-- son dos escrituras separadas y ninguna de las dos implica la otra.
--
-- ReplacingMergeTree(at) porque UN veredicto SÍ se corrige (a diferencia de
-- ops_audit, que es append-only): la clave (case_id, event_id, feedback_id)
-- deja feedback_id como el desambiguador -- dos etiquetas sobre el MISMO
-- (case_id, event_id) son dos filas distintas salvo que compartan también
-- feedback_id, así que corregir un veredicto es reinsertar con el mismo
-- feedback_id y un `at` mayor, nunca un ALTER UPDATE.
CREATE TABLE IF NOT EXISTS isp.ops_feedback
(
    feedback_id  UUID DEFAULT generateUUIDv4(),
    at           DateTime64(3, 'UTC') DEFAULT now64(3),

    -- Objeto etiquetado. Uno de los dos está poblado; el otro va en cero.
    case_id      UUID,
    event_id     UUID,
    src_ip       IPv6,
    customer_id  LowCardinality(String),
    detector_id  LowCardinality(String),
    detector_version UInt16,
    attack_class Enum8('scan' = 1, 'smtp_spam' = 2, 'ddos_out' = 3, 'reflection' = 4,
                        'amplification' = 5, 'anomaly' = 6, 'policy' = 7, 'other' = 99),
    score        UInt8,
    was_mitigated UInt8,          -- 1 si llegó a mit_actions con status ok/partial

    verdict      Enum8('true_positive' = 1, 'false_positive' = 2, 'unclear' = 3),
    -- Taxonomía cerrada del motivo: sin esto, `reason` en texto libre no agrega.
    fp_kind      Enum8('none' = 0, 'legit_mta' = 1, 'legit_scanner' = 2, 'cdn_or_cache' = 3,
                        'backup_or_sync' = 4, 'monitoring' = 5, 'nat_aggregation' = 6,
                        'threshold_too_low' = 7, 'bad_enrichment' = 8, 'other' = 99) DEFAULT 'none',
    reason       String,          -- obligatorio si verdict='false_positive'
    labeled_by   LowCardinality(String),
    source       Enum8('cli' = 1, 'ui' = 2, 'import' = 3) DEFAULT 'cli'
)
ENGINE = ReplacingMergeTree(at)
PARTITION BY toYYYYMM(at)
ORDER BY (case_id, event_id, feedback_id)
-- toDateTime(at): TTL exige DateTime/Date, no DateTime64(3,'UTC').
TTL toDateTime(at) + INTERVAL 730 DAY DELETE;
