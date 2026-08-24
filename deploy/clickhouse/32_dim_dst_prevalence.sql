-- 32_dim_dst_prevalence.sql [E08]
--
-- T-055 (E08-T06) -- E08 §5.2, §4.7.2, §D3 · E00b D-13.
--
-- Guarda estructural contra el falso positivo del tipo "8.8.8.8": arranque
-- en frío con los resolvers públicos del prototipo, marcados source='seed'
-- para que el reporte semanal de E12 pueda distinguir qué semillas ya
-- confirmó el aprendizaje real. La mantiene el proceso `engine` cada hora
-- (E08, fase 2); NO se edita a mano salvo filas con source='manual'. La
-- guarda REAL es la prevalencia aprendida (E08-T14, fase 2); esta semilla
-- solo conserva la lección del incidente, no el mecanismo. Depende de
-- 00_database.sql.

CREATE TABLE IF NOT EXISTS isp.dim_dst_prevalence
(
    dst_ip           IPv6,
    proto            UInt8,
    dst_port         UInt16,

    uniq_customers   UInt32,                 -- clientes distintos que lo usaron
    active_customers UInt32,                 -- base activa en el mismo período
    prevalence       Float32,                -- uniq_customers / active_customers
    days_observed    UInt16,
    first_seen       DateTime('UTC'),
    last_seen        DateTime('UTC'),

    source           Enum8('learned'=1, 'seed'=2, 'manual'=3) DEFAULT 'learned',
    label            LowCardinality(String) DEFAULT '',
    updated_at       DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (dst_ip, proto, dst_port)
TTL toDateTime(last_seen) + INTERVAL 30 DAY DELETE WHERE source = 'learned';

-- Los ocho resolvers públicos del prototipo, UDP/53, más sus equivalentes
-- IPv6 (E08 §4.7.2). source='seed': el TTL de arriba no las alcanza (el
-- WHERE del DELETE es solo sobre 'learned').
INSERT INTO isp.dim_dst_prevalence
    (dst_ip, proto, dst_port, uniq_customers, active_customers, prevalence, days_observed, first_seen, last_seen, source, label)
VALUES
    (toIPv6('::ffff:8.8.8.8'),         17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'google_dns'),
    (toIPv6('2001:4860:4860::8888'),   17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'google_dns'),
    (toIPv6('::ffff:8.8.4.4'),         17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'google_dns'),
    (toIPv6('2001:4860:4860::8844'),   17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'google_dns'),
    (toIPv6('::ffff:1.1.1.1'),         17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'cloudflare_dns'),
    (toIPv6('2606:4700:4700::1111'),   17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'cloudflare_dns'),
    (toIPv6('::ffff:1.0.0.1'),         17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'cloudflare_dns'),
    (toIPv6('2606:4700:4700::1001'),   17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'cloudflare_dns'),
    (toIPv6('::ffff:9.9.9.9'),         17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'quad9_dns'),
    (toIPv6('2620:fe::fe'),            17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'quad9_dns'),
    (toIPv6('::ffff:149.112.112.112'), 17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'quad9_dns'),
    (toIPv6('2620:fe::9'),             17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'quad9_dns'),
    (toIPv6('::ffff:208.67.222.222'),  17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'opendns'),
    (toIPv6('2620:119:35::35'),        17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'opendns'),
    (toIPv6('::ffff:208.67.220.220'),  17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'opendns'),
    (toIPv6('2620:119:53::53'),        17, 53, 0, 0, 0, 0, now(), now(), 'seed', 'opendns');
