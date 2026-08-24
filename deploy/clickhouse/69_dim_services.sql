-- 69_dim_services.sql [E10]
--
-- T-079 (E10-T01) -- E10 §5.2, §4.10.1 · E00d F-2 · E00b D-13 · E10 §9.1 Q6.
--
-- Tabla + diccionario nuevos que E00 §4.5.1 no lista (Q6): los declara E10
-- porque es quien los necesita para que el panel diga '25/tcp SMTP' en vez
-- de '6 25'; E11 los reusa para el texto de la regla que deja en el router.
-- D-13 fijó este archivo en 71_ y E00d F-2 lo bajó a 69_: va ANTES de
-- 70_v_panel.sql porque las vistas del panel llaman a isp_svc_str (creada
-- en 69b_udf_render.sql), que hace dictGet sobre dict_service_names -- no
-- reintroducir el número viejo.
--
-- dict_service_names es COMPLEX_KEY_HASHED con clave (proto, port), que YA
-- es una tupla (E00c C-5): la llamada es dictGetString(..., (toUInt8(p),
-- toUInt16(port))), SIN tuple() extra. Envolverla en tuple() de más rompe
-- la llamada tan silenciosamente como olvidarla en un IP_TRIE.
--
-- `risk` es peso operativo para colorear el panel cuando el servicio
-- aparece como destino de tráfico saliente masivo. NO es un umbral y NO
-- entra en el score de ningún detector (eso es de E05/§4 de cada familia):
-- es exclusivamente color.
--
-- Depende de 00_database.sql.

CREATE TABLE IF NOT EXISTS isp.dim_services
(
    proto      UInt8,                               -- IANA
    port       UInt16,
    name       LowCardinality(String),               -- 'SMTP', 'DNS', 'Telnet'
    -- Peso operativo del servicio cuando aparece como destino de tráfico
    -- saliente masivo. NO es un umbral ni entra en el score (eso es de
    -- E05): es color en el panel.
    risk       Enum8('info' = 0, 'notable' = 1, 'high' = 2) DEFAULT 'info',
    notes      String DEFAULT '',
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (proto, port);

CREATE DICTIONARY IF NOT EXISTS isp.dict_service_names
(
    proto UInt8,
    port  UInt16,
    name  String DEFAULT '',
    risk  UInt8  DEFAULT 0
)
PRIMARY KEY proto, port
SOURCE(CLICKHOUSE(TABLE 'dim_services' DB 'isp'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 600 MAX 1200);

-- Semilla de ~65 filas (E10 §5.2 pide ~60; se seedea con margen). Las
-- explícitas de §5.2 se conservan tal cual (SMTP/Telnet/Memcached/HTTPS/
-- BitTorrent, etc.); se completa con servicios reales conocidos agrupados
-- por la misma lógica de la tabla de §5.2: spam saliente, los puertos que
-- más escanea una botnet, escaneo de servicios explotables, reflectores
-- clásicos de E08 (dim_amp_ports), y contexto de tráfico legítimo que
-- explica el falso positivo típico ("90% de lo que manda es 443").
--
-- Los separadores por grupo que documentaban cada tramo se sacaron de la
-- lista de VALUES (quedan en este párrafo): ClickHouse envía este INSERT por
-- ValuesBlockInputFormat, que no admite un comentario `--` entre dos tuplas
-- -- "Cannot parse input: expected '(' before...". Grupos, en orden: spam
-- saliente; puertos de botnet más sus alt-ports (Mirai escanea 2222/2323
-- tanto como 22/23); escaneo de servicios explotables; gestión RouterOS del
-- propio ISP (vector de E11); reflectores clásicos de E08/dim_amp_ports;
-- fuente conocida de falsos positivos de fanout (STUN/BitTorrent); VoIP;
-- VPN de sitio a sitio; contexto ("90% es 443"); correo del lado cliente;
-- infraestructura de red normal. Las líneas en blanco no rompen el parser.
INSERT INTO isp.dim_services
    (proto, port, name, risk, notes)
VALUES
    (6,  25,    'SMTP',                 'high',    'objetivo directo del negocio: spam saliente'),
    (6,  465,   'SMTPS',                'high',    ''),
    (6,  587,   'Submission',           'high',    ''),

    (6,  22,    'SSH',                  'high',    ''),
    (6,  2222,  'SSH-Alt',              'high',    'alt-port frecuente de brute force'),
    (6,  23,    'Telnet',               'high',    ''),
    (6,  2323,  'Telnet-Alt',           'high',    'alt-port clásico de botnets IoT tipo Mirai'),
    (6,  3389,  'RDP',                  'high',    ''),
    (6,  5900,  'VNC',                  'high',    ''),

    (6,  445,   'SMB',                  'high',    ''),
    (6,  139,   'NetBIOS',              'high',    ''),
    (6,  1433,  'MSSQL',                'high',    ''),
    (6,  3306,  'MySQL',                'high',    ''),
    (6,  5432,  'PostgreSQL',           'high',    ''),
    (6,  6379,  'Redis',                'high',    ''),
    (6,  27017, 'MongoDB',              'high',    ''),
    (6,  21,    'FTP',                  'high',    ''),
    (6,  111,   'Portmap',              'high',    ''),
    (17, 111,   'Portmap',              'high',    ''),
    (6,  2049,  'NFS',                  'high',    ''),
    (17, 2049,  'NFS',                  'high',    ''),
    (6,  1521,  'Oracle-DB',            'high',    ''),
    (6,  2181,  'ZooKeeper',            'high',    'expuesto sin auth = RCE conocido'),
    (6,  9200,  'Elasticsearch',        'high',    'expuesto sin auth = fuga de datos conocida'),
    (6,  9300,  'Elasticsearch-Transport', 'high', ''),
    (6,  7547,  'TR-069',               'high',    'vector de infección de CPE (Mirai/Annie)'),

    (6,  8291,  'Winbox',               'high',    'gestión MikroTik: blanco de escaneo directo'),
    (6,  8728,  'RouterOS-API',         'high',    ''),
    (6,  8729,  'RouterOS-API-SSL',     'high',    ''),

    (17, 53,    'DNS',                  'high',    ''),
    (17, 123,   'NTP',                  'high',    ''),
    (17, 1900,  'SSDP',                 'high',    ''),
    (17, 11211, 'Memcached',            'high',    ''),
    (17, 389,   'CLDAP',                'high',    ''),
    (17, 19,    'Chargen',              'high',    ''),
    (17, 17,    'QOTD',                 'high',    ''),
    (17, 161,   'SNMP',                 'high',    'reflector; ver dim_amp_ports snmp_v2'),
    (17, 69,    'TFTP',                 'high',    'reflector; ver dim_amp_ports tftp'),

    (17, 3478,  'STUN',                 'notable', ''),
    (6,  3478,  'STUN',                 'notable', ''),
    (17, 6881,  'BitTorrent',           'notable', ''),
    (6,  6881,  'BitTorrent',           'notable', ''),

    (17, 5060,  'SIP',                  'notable', ''),
    (6,  5060,  'SIP',                  'notable', ''),
    (17, 5061,  'SIPS',                 'notable', ''),

    (17, 500,   'IKE',                  'notable', ''),
    (17, 4500,  'IPsec-NAT-T',          'notable', ''),
    (6,  1723,  'PPTP',                 'notable', ''),

    (6,  80,    'HTTP',                 'info',    ''),
    (6,  443,   'HTTPS',                'info',    ''),
    (17, 443,   'QUIC',                 'info',    ''),
    (6,  8080,  'HTTP-Alt',             'info',    ''),
    (6,  8443,  'HTTPS-Alt',            'info',    ''),

    (6,  110,   'POP3',                 'info',    ''),
    (6,  995,   'POP3S',                'info',    ''),
    (6,  143,   'IMAP',                 'info',    ''),
    (6,  993,   'IMAPS',                'info',    ''),
    (6,  990,   'FTPS',                 'info',    ''),

    (17, 67,    'DHCP-Server',          'info',    ''),
    (17, 68,    'DHCP-Client',          'info',    ''),
    (17, 547,   'DHCPv6-Server',        'info',    ''),
    (17, 546,   'DHCPv6-Client',        'info',    ''),
    (6,  179,   'BGP',                  'info',    ''),
    (17, 1194,  'OpenVPN',              'info',    ''),
    (6,  1194,  'OpenVPN',              'info',    ''),
    (17, 51820, 'WireGuard',            'info',    '');
