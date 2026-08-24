-- 39b_ops_reputation_self.sql [E04]
--
-- T-064 (E04-T09) -- E04 §4.9.3 · E00f H-1 · E03 §4.9.1.
--
-- Autochequeo: ¿estamos listados nosotros? Es la métrica de negocio del
-- proyecto entero -- "cuidar la reputación de las IPs públicas del ISP" es
-- el objetivo declarado, y sin medirla no hay forma de saber si el sistema
-- cumple. La puebla el job diario que ejecuta el proceso `watchdog` de E12
-- (la lógica del job es de E04, E04 §4.9.3); el sistema salta prefijos no
-- ruteables (RFC1918, 100.64/10, ULA fc00::/7) antes de consultar, porque
-- esas IPs no están en ninguna lista y nunca van a estarlo (P6, §4.1.4).
--
-- NÚMERO -- H-1, bloqueante de arranque. Esta tabla se llamaba 91_ y
-- v_reputation_self, la vista de E10 que la lee, se crea en 70_v_panel.sql:
-- 70 < 91, así que el CREATE VIEW corría ANTES de que la tabla existiera,
-- abortaba 70_v_panel.sql entero y con él todo lo que sigue en el
-- instalador -- incluido 95_roles_grants.sql, o sea todos los usuarios del
-- sistema. De las dos salidas que H-1 ofrecía (adelantar la tabla o mover
-- la vista al bloque 9x), E03 §4.9.1 elige adelantar la tabla ACÁ, en
-- 39b_ -- después de 39_v_ops_data_health.sql y antes de 40_det.sql --
-- para no partir en dos el archivo de vistas del panel. El número sale del
-- bloque 9x del layout, pero la épica dueña sigue siendo E04.
--
-- Por D-13, el orden lexicográfico es por BYTES y no por locale: un `sort`
-- con locale ordena '39b_' antes de '39_' y reintroduce exactamente el bug
-- que este archivo resuelve. Por bytes, '39_' < '39b_' < '40_', que es el
-- orden correcto.
CREATE TABLE IF NOT EXISTS isp.ops_reputation_self
(
    checked_at  DateTime('UTC'),
    ip          IPv6,
    prefix      String,
    list_id     LowCardinality(String),
    listed      UInt8,
    detail      String DEFAULT '',        -- código de retorno de la DNSBL
    first_seen  DateTime('UTC') DEFAULT now(),
    customer_id LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(checked_at)
PARTITION BY toYYYYMM(checked_at)
ORDER BY (ip, list_id)
TTL checked_at + INTERVAL 365 DAY;
