-- 0A_dim_exporters.sql [E04]
--
-- T-063 (E04-T08) -- E04 §4.6 · E00b D-16 · E00e G-2 · E03 §4.9.1.
--
-- Registro de exportadores (dim_exporters) y de sus interfaces
-- (dim_exporter_ifaces). E01 lo lee en runtime para resolver sampling y
-- seq_mode por (IP de origen del datagrama, observation domain); E10 lo lee
-- para el panel; v_exporter_status (11_v_exporter_status.sql, más adelante
-- en el layout porque necesita isp.flows_raw de 10_) lo cruza contra lo que
-- realmente llega.
--
-- G-2: dim_exporter_ifaces va en ESTE archivo y no en uno propio -- misma
-- lógica que 05/06/07 con sus diccionarios: la tabla y su tabla de detalle
-- comparten archivo cuando el layout de E03 §4.9.1 así lo fija.

CREATE TABLE IF NOT EXISTS isp.dim_exporters
(
    -- Identidad de RESOLUCIÓN: el collector llega con (IP origen del
    -- datagrama, obs_domain_id) y necesita saber quién es. Por eso la
    -- ORDER BY es por IP.
    exporter_ip     IPv6,
    -- 0 = comodín: aplica a todos los observation domains de ese exportador.
    -- Una fila específica (obs_domain_id > 0) gana sobre la comodín.
    obs_domain_id   UInt32 DEFAULT 0,

    -- Identidad ESTABLE, la que viaja a flows_raw.exporter_id y a las
    -- métricas. Varias filas pueden compartir exporter_id: un router que
    -- exporta desde su loopback y desde una interfaz física son dos IPs y
    -- un solo equipo.
    exporter_id     LowCardinality(String),

    hostname        String DEFAULT '',
    site            LowCardinality(String) DEFAULT '',
    vendor          LowCardinality(String) DEFAULT '',   -- 'mikrotik','cisco','juniper',...
    os_version      String DEFAULT '',
    role            Enum8('unknown'=0,'border'=1,'core'=2,'access'=3,'cgnat'=4,'bng'=5) DEFAULT 'unknown',

    -- Escalón 2 de la escalera de sampling de E00 §4.2.2. 0 = sin override
    -- (se cae a SEC_SAMPLING_DEFAULT). 1 = "este router NO muestrea"
    -- (declaración explícita, distinta de "no sé"). Arregla la deuda #6 del
    -- prototipo.
    sampling_override UInt32 DEFAULT 0,

    -- Cómo interpretar el campo de secuencia del datagrama, para contar
    -- pérdida sin falsos positivos. Lo consume E01. Entra por D-16: sin esta
    -- columna, exporters.yaml declaraba `seq_mode` y la tabla no podía
    -- guardarlo -- el round-trip archivo <-> tabla que `secisp config
    -- export` tiene que reproducir quedaba roto en una dirección.
    --   auto     = inferir por protocolo (IPFIX/v9 = record, sFlow/v5 = datagram)
    --   datagram = la secuencia cuenta DATAGRAMAS
    --   record   = la secuencia cuenta REGISTROS exportados
    seq_mode        Enum8('auto'=0,'datagram'=1,'record'=2) DEFAULT 'auto',

    -- Espejo declarativo del bloque `obs_domains:` de exporters.yaml
    -- (E04 §4.11): pares (obs_domain_id -> sampling_override). Vive SOLO en
    -- la fila comodín (obs_domain_id = 0); en las filas específicas va
    -- vacío. `config apply` lo expande a una fila por dominio; `config
    -- export` colapsa las filas específicas de vuelta al mapa -- así el
    -- round-trip es exacto sin que la clave de resolución (E04 §4.6.1)
    -- cambie de forma. Misma razón D-16 que seq_mode: sin esta columna el
    -- round-trip también se rompía.
    obs_domains     Map(UInt32, UInt32) DEFAULT map(),

    -- Lo que el operador declara que el equipo exporta. Se compara con lo
    -- que realmente llega y la diferencia se alerta (v_exporter_status,
    -- E04 §4.6.2). Responde P3 y P4 con datos en vez de con suposiciones.
    expect_tcp_flags    UInt8 DEFAULT 1,
    expect_if_direction UInt8 DEFAULT 0,
    expect_ipv6         UInt8 DEFAULT 1,

    -- Timeouts configurados en el router. Entran en el presupuesto de MTTD:
    -- el active-timeout DOMINA la latencia de detección (E00 §1.4). E12 los
    -- usa para calcular el MTTD teórico y contrastarlo con el medido.
    active_timeout_seconds   UInt16 DEFAULT 60,
    inactive_timeout_seconds UInt16 DEFAULT 15,

    -- ¿Es un equipo donde E11 aplica address-lists? Distinto de "exporta flujos".
    mitigation_enabled UInt8 DEFAULT 0,

    is_enabled      UInt8 DEFAULT 1,
    notes           String DEFAULT '',
    created_at      DateTime('UTC') DEFAULT now(),
    updated_at      DateTime64(3,'UTC') DEFAULT now64(3),
    updated_by      LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (exporter_ip, obs_domain_id);

-- Interfaces del equipo, clave por exporter_id -- NO por exporter_ip: la
-- interfaz es del EQUIPO, no de la dirección desde la que exporta (E04
-- §4.6). La usa E01 para el chequeo cruzado de dirección de D4 (§4.6.3,
-- sec_enrich_dir_mismatch_total) y E10 para el panel de interfaces.
CREATE TABLE IF NOT EXISTS isp.dim_exporter_ifaces
(
    exporter_id  LowCardinality(String),
    if_index     UInt32,                    -- el que viene en in_if/out_if
    if_name      String DEFAULT '',         -- 'ether1', 'sfp-plus1', 'pppoe-juan'
    if_role      Enum8('unknown'=0,'upstream'=1,'peering'=2,'customer'=3,'internal'=4,'cgnat'=5) DEFAULT 'unknown',
    speed_bps    UInt64 DEFAULT 0,
    is_enabled   UInt8 DEFAULT 1,
    updated_at   DateTime64(3,'UTC') DEFAULT now64(3),
    updated_by   LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (exporter_id, if_index);
