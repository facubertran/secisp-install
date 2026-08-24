-- 06_dim_asn_meta.sql [E04]
--
-- T-064 (E04-T09) -- E04 §4.7.2 · E00b D-7 · E00e G-2 · E03 §4.9.1 · E04-14.
--
-- Prefijo -> ASN (dim_asn, con su vista _v6) y metadata curada POR ASN
-- (dim_asn_meta): is_cdn / is_cloud, que no viene de ninguna base automática
-- (D-7). Alimenta dict_asn y dict_asn_meta, que crea 08_dict.sql -- G-2
-- encontró que este archivo declaraba las tablas y 08_dict.sql no envolvía
-- ninguna de las dos en un diccionario; acá quedan solo las tablas y la
-- vista, los diccionarios van juntos en 08_dict.sql y NO acá (misma regla
-- que dim_net_prefixes / 05_dim_net_prefixes.sql).

-- Prefijo -> ASN. Fuentes intercambiables (MaxMind, un feed BGP, o un
-- INSERT manual para corregir un caso puntual).
CREATE TABLE IF NOT EXISTS isp.dim_asn
(
    prefix     String,                        -- forma humana; la vista _v6 la mapea
    asn        UInt32,
    as_name    String DEFAULT '',
    cc         LowCardinality(String) DEFAULT '',
    -- Precedencia de fuentes al resolver el conflicto de un mismo prefijo
    -- declarado por más de una: manual (3) > bgp (2) > maxmind (1).
    source     Enum8('maxmind' = 1, 'bgp' = 2, 'manual' = 3) DEFAULT 'maxmind',
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (prefix, source);

-- dim_asn_v6 -- CON el prefijo `v_` a diferencia de dim_net_prefixes_v6: la
-- excepción de nombre que fija E00 (D-34/E04 §4.1.2) es puntual a esa vista,
-- no a las tres que alimentan diccionarios IP_TRIE de E04.
--
-- IP_TRIE exige clave única por prefijo: si dim_asn tiene dos fuentes para
-- el mismo prefijo (p.ej. maxmind Y manual), esta vista se queda con la de
-- mayor precedencia vía `LIMIT 1 BY prefix` sobre un ORDER BY que pone
-- primero el rango de mayor source (E04 §4.7.2).
CREATE OR REPLACE VIEW isp.dim_asn_v6 AS
SELECT prefix, asn, as_name, cc
FROM
(
    SELECT
        if(position(prefix, ':') > 0, prefix,
           concat('::ffff:', splitByChar('/', prefix)[1], '/',
                  toString(96 + toUInt16(splitByChar('/', prefix)[2])))) AS prefix,
        asn, as_name, cc, toUInt8(source) AS src_rank
    FROM isp.dim_asn FINAL
)
ORDER BY prefix, src_rank DESC
-- Con el ORDER BY de arriba, la primera fila de cada prefix es la de mayor
-- src_rank: manual(3) le gana a bgp(2), que le gana a maxmind(1).
LIMIT 1 BY prefix;

-- Metadata POR ASN. Es lo que NO viene de ninguna base automática y hay que
-- curar a mano: qué ASNs son CDN o cloud (D-7). Se audita de un vistazo,
-- igual que dim_amp_ports (31_dim_amp_ports.sql).
--
-- is_isp_own queda en 0 para TODA la semilla de abajo, a propósito: el/los
-- ASN del propio ISP son configuración (SEC_ISP_ASN, E04-P4), nunca un
-- número cableado en el DDL -- nada del set puede asumir un ISP en
-- particular. Cargar esa fila es un INSERT que hace el operador, no la
-- semilla de esta épica.
CREATE TABLE IF NOT EXISTS isp.dim_asn_meta
(
    asn        UInt32,
    as_name    String DEFAULT '',
    org        String DEFAULT '',
    is_cdn     UInt8 DEFAULT 0,
    is_cloud   UInt8 DEFAULT 0,
    is_isp_own UInt8 DEFAULT 0,   -- el/los ASN del propio ISP
    notes      String DEFAULT '',
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    updated_by LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (asn);

-- Semilla de E04-14: >= 30 ASNs reales de CDN/cloud, curados a mano.
-- dictGetUInt8('isp.dict_asn_meta', 'is_cdn', toUInt64(13335)) tiene que
-- dar 1 apenas se aplica el layout (Cloudflare), sin esperar a ningún job
-- de importación -- por eso la semilla vive en el archivo de su tabla, no
-- en un bootstrap externo (mismo patrón que 31_dim_amp_ports.sql).
--
-- is_cdn=1 son proveedores cuyo negocio central es distribuir contenido de
-- terceros desde POPs cercanos al usuario (Akamai, Fastly, Cloudflare,
-- Limelight/Edgio, Edgecast, Incapsula, StackPath, CacheFly) o que operan su
-- propio CDN a gran escala para su propio contenido (Google/YouTube,
-- Facebook/Meta, Netflix -- con sus cachés OCA, Apple). is_cloud=1 son
-- proveedores de cómputo/hosting genérico (AWS, Azure, GCP, Alibaba Cloud,
-- Tencent Cloud, Oracle Cloud, IBM/SoftLayer, OVH, Hetzner, DigitalOcean,
-- Vultr, Linode, Packet/Equinix Metal). Los tres grandes (Google, Amazon,
-- Microsoft) llevan las dos banderas porque su ASN sirve tráfico de CDN
-- (Cloud CDN / CloudFront / Azure CDN) y de cómputo genérico por igual.
INSERT INTO isp.dim_asn_meta
    (asn, as_name, org, is_cdn, is_cloud, notes)
VALUES
    (13335,  'CLOUDFLARENET',                'Cloudflare, Inc.',                            1, 0, 'CDN/DDoS protection, Anycast'),
    (15169,  'GOOGLE',                       'Google LLC',                                   1, 1, 'CDN propio (YouTube/GGC) + Google Cloud CDN'),
    (19527,  'GOOGLE',                       'Google LLC',                                   1, 1, 'Rango secundario de Google'),
    (396982, 'GOOGLE-CLOUD-PLATFORM',        'Google LLC',                                   0, 1, 'Google Cloud Platform (GCP)'),
    (16509,  'AMAZON-02',                    'Amazon.com, Inc.',                             1, 1, 'AWS: EC2/S3 + CloudFront'),
    (14618,  'AMAZON-AES',                   'Amazon.com, Inc.',                             1, 1, 'AWS, rango histórico'),
    (8075,   'MICROSOFT-CORP-MSN-AS-BLOCK',  'Microsoft Corporation',                        1, 1, 'Azure + Azure CDN/Front Door'),
    (8068,   'MICROSOFT-CORP-MSN-AS-BLOCK',  'Microsoft Corporation',                        0, 1, 'Azure, rango adicional'),
    (8069,   'MICROSOFT-CORP-MSN-AS-BLOCK',  'Microsoft Corporation',                        0, 1, 'Azure, rango adicional'),
    (3598,   'MICROSOFT',                    'Microsoft Corporation',                        0, 1, 'Microsoft, rango histórico'),
    (20940,  'AKAMAI-ASN1',                  'Akamai International B.V.',                    1, 0, 'CDN, POPs internacionales'),
    (16625,  'AKAMAI-AS',                    'Akamai Technologies, Inc.',                     1, 0, 'CDN, ASN original de Akamai'),
    (54113,  'FASTLY',                       'Fastly, Inc.',                                 1, 0, 'CDN'),
    (32934,  'FACEBOOK',                     'Meta Platforms, Inc.',                          1, 0, 'CDN propio (contenido/vídeo de Meta)'),
    (2906,   'NETFLIX-ASN',                  'Netflix, Inc.',                                1, 0, 'CDN propio (Open Connect / OCA)'),
    (40027,  'NETFLIX-STREAMING-SERVICES',   'Netflix Streaming Services, Inc.',              1, 0, 'CDN propio (Open Connect / OCA)'),
    (22822,  'LLNW',                         'Limelight Networks, Inc. (hoy Edgio)',          1, 0, 'CDN'),
    (15133,  'EDGECAST',                     'Edgecast Inc. (hoy Edgio)',                     1, 0, 'CDN'),
    (19551,  'INCAPSULA',                    'Imperva, Inc.',                                 1, 0, 'CDN + WAF (Incapsula)'),
    (33438,  'STACKPATH',                    'StackPath, LLC',                                1, 0, 'CDN'),
    (30060,  'CACHENETWORKS',                'CacheFly',                                      1, 0, 'CDN'),
    (714,    'APPLE-ENGINEERING',            'Apple Inc.',                                    1, 0, 'CDN propio (App Store/iCloud)'),
    (16276,  'OVH',                          'OVH SAS',                                       0, 1, 'Hosting/cloud europeo'),
    (24940,  'HETZNER-AS',                   'Hetzner Online GmbH',                           0, 1, 'Hosting/cloud europeo'),
    (14061,  'DIGITALOCEAN-ASN',             'DigitalOcean, LLC',                              0, 1, 'Cloud'),
    (20473,  'AS-CHOOPA',                    'The Constant Company, LLC (Vultr)',             0, 1, 'Cloud'),
    (63949,  'LINODE-AP',                    'Linode, LLC',                                    0, 1, 'Cloud'),
    (36351,  'SOFTLAYER',                    'SoftLayer Technologies Inc. (IBM Cloud)',       0, 1, 'Cloud'),
    (31898,  'ORACLE-BMC-31898',             'Oracle Corporation',                            0, 1, 'Oracle Cloud Infrastructure (OCI)'),
    (54825,  'PACKET',                       'Packet Host, Inc. (hoy Equinix Metal)',         0, 1, 'Bare-metal cloud'),
    (45102,  'ALIBABA-CN-NET',               'Alibaba (US) Technology Co., Ltd.',             0, 1, 'Alibaba Cloud'),
    (37963,  'CNNIC-ALIBABA-CN-NET-AP',      'Hangzhou Alibaba Advertising Co., Ltd.',        0, 1, 'Alibaba Cloud'),
    (132203, 'TENCENT-NET-AP-CN',            'Tencent Building, Kejizhongyi Avenue',          0, 1, 'Tencent Cloud');
