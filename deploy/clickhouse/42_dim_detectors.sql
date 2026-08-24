-- 42_dim_detectors.sql [E05]
--
-- T-073 (E05-T05) -- E05 §5.1, §5.8 · E00 §4.3.1 · E00b D-13.
--
-- Catálogo detector_id -> family, mode. Lo reescribe el motor al arrancar y
-- en cada recarga en caliente (E05 §5.8): el motor es la fuente de verdad en
-- runtime. Esta semilla es lo que existe ANTES de que el motor haya corrido
-- una sola vez -- sin ella, `isp.v_det_detectors` (43_v_det.sql, T-074) y
-- `isp.dict_detector_family` (08_dict.sql, T-066) arrancan vacíos, y
-- `policy.yaml` de E11 (ola 8) no tiene contra qué validar sus 28 entradas
-- (E00e G-1, mismo patrón: un objeto que el layout no llena no existe para
-- quien lo consulta).
--
-- La vista v_det_detectors y el diccionario dict_detector_family NO se
-- declaran acá: son de T-074 (43_v_det.sql) y T-066 (08_dict.sql) por la
-- regla de propiedad de archivos.

CREATE TABLE IF NOT EXISTS isp.dim_detectors
(
    detector_id LowCardinality(String), detector_version UInt16,
    attack_class LowCardinality(String), family LowCardinality(String),
    -- Modo EFECTIVO resuelto en runtime (flag > env > yaml > shadow). Lo reescribe
    -- el motor al arrancar y en cada recarga en caliente. E11 lo necesita para
    -- distinguir alert de mitigate sin leer la config del motor: sin esta columna,
    -- el mitigador no tiene forma de saber si un caso es accionable o si su
    -- detector todavía está calibrando.
    mode LowCardinality(String),        -- 'off' | 'shadow' | 'alert' | 'mitigate'
    mode_updated_at DateTime64(3,'UTC') DEFAULT now64(3),
    window_seconds UInt32,              -- Spec.Window.Length en segundos
    cadence_seconds UInt32,             -- Spec.Window.EffectiveCadence() (D-27)
    is_composite UInt8 DEFAULT 0,       -- 1 si implementa CompositeDetector (D-23)
    description String, params_hash String,
    registered_at DateTime64(3,'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(registered_at) ORDER BY (detector_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- Semilla: los 28 detector_id conocidos del proyecto (E06 5 + E07 7 + E08 11
-- + E09 5 = 28, número que docs/tasks/ola-08-panel-y-mitigacion-dry-run.md
-- §T-imports cita literal: "28 detector_id reales de E06 (5), E07 (7), E08
-- (11) y E09 (5)"). Procedencia de cada detector_id, familia y modo:
--
-- scan.* (5, E06 §4.12 / docs/tasks/ola-07-deteccion-f1.md T-241..T-246):
--   horizontal, vertical, syn_unanswered, sweep_slow, coordinated. Family de
--   cada uno sale de su Spec{} en E06 §4.12 (cardinality|flags|cardinality).
--
-- ddos.* (6, E08 §4.6 / §5.6): src_flood, carpet_bombing, victim_convergence,
--   syn_flood, amp_request, spoofed_egress. Class/family de cada uno sale del
--   encabezado "— v1, clase X, ventana Ns, clave K, familia Y" de E08 §4.6.*.
--
-- refl.* (5, E08 §4.6.6 / §5.6): dns, ntp, ssdp, memcached, generic. Mismo
--   patrón de encabezado que ddos.*: clase reflection, familia service.
--
-- smtp.* (7, E07 §4.5.8, tabla "Resumen operativo"): small_session, stalled,
--   low_rate, fanout, refused, volume, port25_policy. La columna "Familia" de
--   esa tabla es la fuente; smtp.port25_policy sale con family='policy' tal
--   como la tabla la declara -- fuera del set {volume,cardinality,flags,
--   service,session,baseline} de framework.Family (E05 §4.3), una divergencia
--   real de la spec que se transcribe literal en vez de forzarla a 'service'
--   (que es lo que eligió ddos.spoofed_egress, el otro detector attack_class
--   ='policy', para el mismo dilema): documentada acá, a resolver por E07/E05
--   cuando se declare el Spec{} real (ola 10).
--
-- anomaly.* (5, E09 §4.11, tabla "Los cinco detectores"): volume_spike,
--   fanout_spike, level_shift, new_service, service_wave. Los cinco son
--   Class=ClassAnomaly, Family=FamilyBaseline por declaración expresa de esa
--   sección ("Todos: Class = ClassAnomaly (6), Family = FamilyBaseline (6)").
--
-- Modo: ADR-011 fija shadow como default de todo detector nuevo, y las tres
-- épicas que ya declaran su variable SEC_DETECT_MODE_<ID> (E06 §5.6, E08
-- §5.6) confirman shadow como default compilado sin excepciones -- ninguna
-- vale 'alert' todavía. La partición mode acá NO es "activo si default
-- compilado shadow": la mayoría de los detectores default a shadow en su
-- propio código pero DEPENDE de una épica que esta ola todavía no implementa
-- (no existe internal/detect/{smtp,ddos,anomaly}/*.go, solo el framework).
-- 'shadow' se reserva a los ocho detectores que docs/tasks/ola-07-deteccion-
-- f1.md efectivamente construye en esta fase (los cinco scan.* de E06 más
-- ddos.src_flood/carpet_bombing/victim_convergence de E08 -- los tres, no
-- solo los dos primeros: T-272 de esa ola construye victim_convergence junto
-- a los otros dos, y su propio texto de apertura lo nombra como motivador
-- ["ddos.victim_convergence es el detector que causó el incidente del
-- resolver"]). El resto -- ddos.syn_flood/amp_request/spoofed_egress y
-- refl.* (ola 11), smtp.* (ola 10), anomaly.* (ola 9) -- va en 'off': ningún
-- proceso engine los ejecuta todavía, y 'shadow' en la semilla sin código que
-- lo respalde sería mentir sobre qué corre.
-- Los separadores por familia que documentaban cada tramo de VALUES se
-- sacaron de acá (quedan arriba, en el bloque de cabecera): ClickHouse envía
-- este INSERT por ValuesBlockInputFormat, que no admite un comentario `--`
-- entre dos tuplas de VALUES -- "Cannot parse input: expected '(' before...".
-- El SELECT de humo de §8.2 (T-099) es lo que atrapa esto si alguien reintroduce
-- un comentario acá; las líneas en blanco, en cambio, no rompen el parser.
INSERT INTO isp.dim_detectors
    (detector_id, detector_version, attack_class, family, mode, window_seconds, cadence_seconds, description)
VALUES
    ('scan.horizontal',        1, 'scan',          'cardinality', 'shadow', 60,   60,   'Fanout de destinos de un cliente sobre un mismo puerto (barrido horizontal)'),
    ('scan.vertical',          1, 'scan',          'cardinality', 'shadow', 60,   60,   'Fanout de puertos de un cliente contra un mismo host (barrido vertical)'),
    ('scan.syn_unanswered',    1, 'scan',          'flags',       'shadow', 60,   60,   'SYN sin respuesta hacia multiples destinos: escaneo sin trafico de retorno'),
    ('scan.sweep_slow',        1, 'scan',          'cardinality', 'shadow', 900,  300,  'Barrido lento sostenido 15 min que evade los umbrales de 60 s'),
    ('scan.coordinated',       1, 'scan',          'cardinality', 'shadow', 60,   60,   'Meta-detector: mismo puerto barrido por varios clientes a la vez (botnet)'),

    ('ddos.src_flood',         1, 'ddos_out',      'volume',      'shadow', 10,   10,   'Flood volumetrico por origen (pps/bps) en ventana de 10 s'),
    ('ddos.carpet_bombing',    1, 'ddos_out',      'cardinality', 'shadow', 60,   60,   'Un origen distribuye el flood entre muchos destinos del mismo ISP'),
    ('ddos.victim_convergence',1, 'ddos_out',      'service',     'shadow', 60,   60,   'Muchos origenes convergen sobre el mismo (dst_ip, proto, dst_port)'),
    ('ddos.syn_flood',         1, 'ddos_out',      'flags',       'off',    60,   60,   'Flood de SYN sin ACK por origen (agotamiento de conexion)'),
    ('ddos.amp_request',       1, 'amplification', 'service',     'off',    60,   60,   'El cliente origina requests hacia reflectores de amplificacion'),
    ('ddos.spoofed_egress',    1, 'policy',        'service',     'off',    60,   60,   'Trafico saliente con IP de origen fuera del bloque delegado al exportador'),

    ('refl.dns',               1, 'reflection',    'service',     'off',    60,   60,   'El cliente es reflector de una amplificacion DNS (53/UDP)'),
    ('refl.ntp',               1, 'reflection',    'service',     'off',    60,   60,   'El cliente es reflector de una amplificacion NTP (123/UDP)'),
    ('refl.ssdp',              1, 'reflection',    'service',     'off',    60,   60,   'El cliente es reflector de una amplificacion SSDP (1900/UDP)'),
    ('refl.memcached',         1, 'reflection',    'service',     'off',    60,   60,   'El cliente es reflector de una amplificacion memcached (11211/UDP)'),
    ('refl.generic',           1, 'reflection',    'service',     'off',    60,   60,   'El cliente es reflector de una amplificacion sobre un puerto UDP generico'),

    ('smtp.small_session',     1, 'smtp_spam',     'session',     'off',    3600, 300,  'Sesiones SMTP salientes anormalmente chicas (spam de bajo volumen)'),
    ('smtp.stalled',           1, 'smtp_spam',     'session',     'off',    3600, 300,  'Sesiones SMTP que se cuelgan sin avanzar el protocolo'),
    ('smtp.low_rate',          1, 'smtp_spam',     'session',     'off',    3600, 300,  'Tasa de sesiones SMTP baja pero sostenida, por debajo de smtp.volume'),
    ('smtp.fanout',            1, 'smtp_spam',     'cardinality', 'off',    3600, 300,  'Un cliente habla SMTP con demasiados destinos o ASN distintos'),
    ('smtp.refused',           1, 'smtp_spam',     'flags',       'off',    3600, 300,  'Alta proporcion de sesiones SMTP rechazadas por el destino'),
    ('smtp.volume',            1, 'smtp_spam',     'volume',      'off',    3600, 300,  'Volumen de sesiones SMTP salientes por encima del umbral'),
    ('smtp.port25_policy',     1, 'policy',        'policy',      'off',    3600, 300,  'Cliente sin port25_allowed intenta tcp/25: violacion de politica declarada'),

    ('anomaly.volume_spike',   1, 'anomaly',       'baseline',    'off',    300,  300,  'Pico de pps relativo al perfil baseline del cliente'),
    ('anomaly.fanout_spike',   1, 'anomaly',       'baseline',    'off',    300,  300,  'Fanout de destinos anomalo por debajo del umbral fijo de escaneo'),
    ('anomaly.level_shift',    1, 'anomaly',       'baseline',    'off',    300,  300,  'CUSUM de z_pps: abuso sostenido de baja tasa contra el perfil'),
    ('anomaly.new_service',    1, 'anomaly',       'baseline',    'off',    3600, 3600, 'Cliente habla por primera vez un puerto de abuso que nunca hablo'),
    ('anomaly.service_wave',   1, 'anomaly',       'baseline',    'off',    3600, 3600, 'Brote coordinado de un servicio en todo el ISP (ningun cliente solo)');
