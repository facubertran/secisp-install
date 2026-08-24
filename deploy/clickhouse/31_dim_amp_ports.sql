-- 31_dim_amp_ports.sql [E08]
--
-- T-048 (E08-T04) -- E08 §5.2, §4.6.2 · E00b D-2, D-13, D-32 · E00d F-4.
--
-- Único lugar de verdad de los 25 puertos amplificables: la lee E08
-- (detección, fase 2) y E11 (para elegir rate_limit vs block_service). Las
-- dos ramas del OR de mv_agg_src_port_1m (30_agg_src_port_1m.sql, T-050) la
-- replican literalmente porque una MV no puede leer una tabla (ADR-008); un
-- test de E12 falla si los dos lugares divergen en un solo puerto. Entra
-- desde el día 1 aunque los detectores refl.* sean de fase 2 (T-048 trampa):
-- agregar un puerto después del primer INSERT exige DROP+CREATE de la MV con
-- el sink pausado.

CREATE TABLE IF NOT EXISTS isp.dim_amp_ports
(
    proto            UInt8 DEFAULT 17,
    port             UInt16,
    service          LowCardinality(String),
    detector_id      LowCardinality(String),  -- 'refl.dns' | 'refl.ntp' | 'refl.ssdp'
                                              -- | 'refl.memcached' | 'refl.generic'
    baf_published    Float32,                 -- factor de amplificación publicado (referencia)
    min_resp_pps     UInt32,                  -- umbral de disparo del detector
    min_resp_bpp     UInt32,                  -- bytes por paquete mínimos de la respuesta
    min_amp_factor   Float32,                 -- amp_factor mínimo cuando hay pata entrante
    never_legit      UInt8 DEFAULT 0,         -- 1 = jamás es legítimo hacia Internet
    is_enabled       UInt8 DEFAULT 1,
    updated_at       DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (proto, port);

-- Semilla de E08 §4.6.2: la unión de la lista de E03 (23) y la de E08 (17),
-- 25 puertos (E00b D-2). never_legit = 0 exactamente en 53, 123, 161, 623 y
-- 27015 (columna "legítimo en un cliente" = sí/raro); 1 en los otros veinte.
-- baf_published y min_resp_bpp toman el extremo bajo del rango publicado de
-- §4.6.2 cuando la fila da un rango; min_amp_factor es la mitad de
-- baf_published como default conservador -- E08 (ola 7) lo calibra con
-- datos reales, esta semilla solo tiene que ser estructuralmente correcta.
INSERT INTO isp.dim_amp_ports
    (proto, port, service, detector_id, baf_published, min_resp_pps, min_resp_bpp, min_amp_factor, never_legit)
VALUES
    (17, 11211, 'memcached',              'refl.memcached', 10000, 50,  1300, 5000,  1),
    (17, 123,   'ntp_monlist',            'refl.ntp',        556,  100, 440,  278,   0),
    (17, 19,    'chargen',                'refl.generic',    358,  50,  1000, 179,   1),
    (17, 520,   'ripv1',                  'refl.generic',    131,  50,  500,  65.5,  1),
    (17, 389,   'cldap',                  'refl.generic',    56,   50,  1500, 28,    1),
    (17, 53,    'dns_any',                'refl.dns',        28,   200, 500,  14,    0),
    (17, 1900,  'ssdp',                   'refl.ssdp',       30,   100, 300,  15,    1),
    (17, 3702,  'ws_discovery',           'refl.generic',    10,   50,  300,  5,     1),
    (17, 111,   'portmap',                'refl.generic',    7,    50,  100,  3.5,   1),
    (17, 161,   'snmp_v2',                'refl.generic',    6,    100, 300,  3,     0),
    (17, 1434,  'mssql_monitor',          'refl.generic',    25,   50,  400,  12.5,  1),
    (17, 5678,  'mikrotik_mndp',          'refl.generic',    10,   50,  200,  5,     1),
    (17, 27015, 'steam_a2s',              'refl.generic',    5,    200, 700,  2.5,   0),
    (17, 5353,  'mdns',                   'refl.generic',    2,    100, 200,  1,     1),
    (17, 137,   'netbios_ns',             'refl.generic',    3.8,  100, 200,  1.9,   1),
    (17, 10001, 'ubiquiti_discovery',     'refl.generic',    30,   50,  200,  15,    1),
    (17, 3283,  'apple_remote_desktop',   'refl.generic',    34,   50,  500,  17,    1),
    (17, 17,    'qotd',                   'refl.generic',    140,  50,  100,  70,    1),
    (17, 69,    'tftp',                   'refl.generic',    60,   50,  500,  30,    1),
    (17, 177,   'xdmcp',                  'refl.generic',    35,   50,  200,  17.5,  1),
    (17, 5093,  'sentinel_ldk',           'refl.generic',    43,   50,  300,  21.5,  1),
    (17, 33848, 'jenkins_discovery',      'refl.generic',    8,    50,  200,  4,     1),
    (17, 37810, 'dahua_dvr_discovery',    'refl.generic',    6,    50,  200,  3,     1),
    (17, 5351,  'nat_pmp',                'refl.generic',    4,    100, 100,  2,     1),
    (17, 623,   'ipmi_rmcp',              'refl.generic',    1.5,  100, 100,  0.75,  0);
