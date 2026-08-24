-- 08_dict.sql [E04]
--
-- T-066 (E04-T10) -- E04 §4.1.3, §4.7.2, §4.9.2 · E00b D-35 · E00c C-6 ·
-- E00e G-2 · E03 §4.9.1 · E04-22.
--
-- Los CINCO diccionarios de esquema `isp`: los cuatro de E04 sobre las tres
-- tablas fuente ya escritas (05_dim_net_prefixes.sql, 06_dim_asn_meta.sql,
-- 07_dim_reputation.sql) más dict_detector_family, que es un objeto de E05
-- pero se crea ACÁ por la misma regla que dejó a los otros cuatro fuera del
-- archivo de su tabla (E00e G-2): el layout de E03 §4.9.1 los agrupa todos
-- en un solo archivo, y ninguno vive en el archivo de su tabla fuente.
--
-- ES EL ÚNICO ARCHIVO posterior a las tres tablas de dimensión que envuelve
-- (05, 06, 07): cada CREATE DICTIONARY apunta a una vista `_v6` de esas
-- tablas, y aunque la carga diferida (dictionaries_lazy_load=1, default de
-- ClickHouse) hace que el CREATE no toque la fuente, el primer dictGet SÍ
-- -- y ese primer dictGet lo dispara el SELECT de humo de 09_udf_net.sql,
-- en el mismo `apply` (E04 §4.1.3).
--
-- ADR-008: ninguna MV de ingesta consulta estos diccionarios. Una falla de
-- cualquiera de los cinco degrada la detección/mitigación, nunca la
-- ingesta -- flows_raw sigue insertando igual.
--
-- REGLA DE tuple() (D-35), sin excepciones ambiguas en este archivo:
--   - dict_net_prefixes, dict_asn, dict_reputation -- LAYOUT(IP_TRIE()):
--     clave compleja, el tercer argumento de dictGet* va SIEMPRE tuple(...).
--   - dict_asn_meta -- LAYOUT(HASHED()) con clave SIMPLE `asn` (UInt32):
--     va SIN tuple(). Es la única excepción real, no un descuido.
--   - dict_detector_family -- LAYOUT(COMPLEX_KEY_HASHED()) con
--     PRIMARY KEY detector_id String (C-6): ClickHouse no admite HASHED con
--     clave String sin una columna sustituta numérica que no existe, así
--     que la clave compleja aplica igual que en los IP_TRIE y el dictGet
--     también va con tuple(). El texto de este bloque se coordina con E05
--     §5.4 (dueña del objeto) y con lo que ya consume 40_det.sql
--     (`dictGetOrDefault('isp.dict_detector_family', 'mode', tuple(d),
--     'shadow')`), escrito en el batch anterior de esta misma ola.
--
-- Consumo de las cuatro UDF de red que envuelven a los primeros tres
-- diccionarios: 09_udf_net.sql, el archivo siguiente de este mismo layout.

-- ═══════════════════════════════════════════════════════════════════════════
-- dict_net_prefixes -- E04 §4.1.3. DDL LITERAL fijado por E00, reproducido
-- acá porque es el objeto que esta épica crea y mantiene.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE DICTIONARY IF NOT EXISTS isp.dict_net_prefixes
(
    prefix      String,
    -- DEFAULT 3 (external): lo que no matchea ningún prefijo es, por
    -- definición, de afuera. `unknown` (0) queda reservado para "no pude
    -- consultar", un estado distinto que se distingue en el collector.
    scope       UInt8   DEFAULT 3,
    customer_id String  DEFAULT '',
    ignore_src  UInt8   DEFAULT 0,
    ignore_dst  UInt8   DEFAULT 0,
    label       String  DEFAULT ''
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(TABLE 'dim_net_prefixes_v6' DB 'isp'))
LAYOUT(IP_TRIE())
LIFETIME(MIN 30 MAX 90);

-- ═══════════════════════════════════════════════════════════════════════════
-- dict_asn -- E04 §4.7.2. IP_TRIE: prefijo -> ASN/país del estado actual.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE DICTIONARY IF NOT EXISTS isp.dict_asn
(
    prefix  String,
    asn     UInt32 DEFAULT 0,
    as_name String DEFAULT '',
    cc      String DEFAULT ''
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(TABLE 'dim_asn_v6' DB 'isp'))
LAYOUT(IP_TRIE())
LIFETIME(MIN 300 MAX 900);

-- ═══════════════════════════════════════════════════════════════════════════
-- dict_asn_meta -- E04 §4.7.2. HASHED con clave SIMPLE `asn`: SIN tuple() en
-- ninguna lectura. Es la metadata curada a mano (is_cdn/is_cloud, D7) que
-- reemplaza a CDN_EXCLUDED_COUNTRIES del prototipo.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE DICTIONARY IF NOT EXISTS isp.dict_asn_meta
(
    asn      UInt32,
    as_name  String  DEFAULT '',
    org      String  DEFAULT '',
    is_cdn   UInt8   DEFAULT 0,
    is_cloud UInt8   DEFAULT 0
)
PRIMARY KEY asn
SOURCE(CLICKHOUSE(TABLE 'dim_asn_meta' DB 'isp'))
LAYOUT(HASHED())
LIFETIME(MIN 300 MAX 900);

-- ═══════════════════════════════════════════════════════════════════════════
-- dict_reputation -- E04 §4.9.2. IP_TRIE sobre las listas externas cargadas
-- offline (Spamhaus DROP/EDROP, Cymru Bogons, FireHOL, Feodo/SSLBL). Regla
-- dura de §4.9.2: esto SUBE confidence o alimenta policy.* en shadow, nunca
-- acciona por sí solo.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE DICTIONARY IF NOT EXISTS isp.dict_reputation
(
    prefix     String,
    lists      String  DEFAULT '',
    category   UInt8   DEFAULT 0,
    confidence Float32 DEFAULT 0
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(TABLE 'dim_reputation_v6' DB 'isp'))
LAYOUT(IP_TRIE())
LIFETIME(MIN 600 MAX 1800);

-- ═══════════════════════════════════════════════════════════════════════════
-- dict_detector_family -- objeto de E05 §5.4 (D-35 resuelto por C-6 a favor
-- de esta declaración), creado ACÁ por la regla de agrupamiento de G-2. Su
-- SOURCE es isp.v_det_detectors, que crea 43_v_det.sql (T-074) -- un archivo
-- de número MAYOR que este. Es la ÚNICA excepción de orden de todo el
-- layout, y es legal solo para el CREATE DICTIONARY (nunca para un CREATE
-- VIEW): la carga diferida hace que ClickHouse no resuelva la fuente al
-- crear el diccionario, así que no importa que 43_ todavía no exista cuando
-- este archivo corre (08 < 43). El primer dictGet real sí necesita la
-- fuente resuelta, y para entonces 43_ ya se aplicó (E03 §4.9.1).
--
-- PRIMARY KEY detector_id String: ClickHouse solo admite LAYOUT(HASHED())
-- con clave simple UInt64. Una clave String exige COMPLEX_KEY_HASHED, y
-- COMPLEX_KEY_* exige que toda llamada pase la clave como tuple(...) --
-- exactamente como los tres IP_TRIE de arriba, aunque el layout interno sea
-- distinto. Uso canónico, ya en producción en 40_det.sql:
--   dictGetOrDefault('isp.dict_detector_family', 'mode', tuple(d), 'shadow')
-- ═══════════════════════════════════════════════════════════════════════════
CREATE DICTIONARY IF NOT EXISTS isp.dict_detector_family
(
    detector_id String,
    family      String,
    mode        String
)
PRIMARY KEY detector_id
SOURCE(CLICKHOUSE(TABLE 'v_det_detectors' DB 'isp'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);
