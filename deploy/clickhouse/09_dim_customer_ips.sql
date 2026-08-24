-- 09_dim_customer_ips.sql [E04]
--
-- T-064 (E04-T09) -- E04 §4.8.3 · E03 §4.9.1.
--
-- IP pública -> abonado, con vigencia temporal. Es la tabla de respaldo de
-- SubscriberResolver (E04 §4.8.2): el resolver dinámico (radius -- NUNCA
-- implementado, E04-P1 lo elimina -- o dhcp) la puebla en runtime, y da el
-- histórico forense ("¿quién tenía esta IP el martes a las 3 AM?", V_customer_ips
-- de E10). Con el modelo de origen mixto de P6 (§4.1.4), del lado IPv4 la
-- fuente real hoy es `static` (el customer_id del longest-prefix-match de
-- dim_net_prefixes); esta tabla queda lista para cuando entre dhcp en F2 sin
-- tocar una línea de E10 ni de E11.
--
-- Dimensionamiento (E04-P7, RESPONDIDA): 1.000-20.000 abonados, consistente
-- con el supuesto de E09 §4.4 (~20.000 IPs activas por día). El nombre del
-- archivo lo reserva E03 en el layout de §4.9.1 dentro del bloque 0x de E04
-- (E00d F-2: comparte el número 09 con 09_udf_net.sql, que va DESPUÉS por
-- orden de bytes -- '09_dim_customer_ips.sql' < '09_udf_net.sql').
--
-- No hay diccionario para esta tabla (E04 §4.8.3): un IP_TRIE no soporta
-- rangos temporales y un RANGE_HASHED no soporta claves IP. La resolución
-- temporal es en SQL (consulta forense puntual) o en memoria en el collector
-- (mapa exacto de sesiones abiertas).
CREATE TABLE IF NOT EXISTS isp.dim_customer_ips
(
    ip           IPv6,                          -- forma IPv4-mapped (E00 §4.1.1)
    customer_id  LowCardinality(String),
    started_at   DateTime('UTC'),
    -- '2106-02-07' (máximo de DateTime) = sesión abierta. Se cierra al ver
    -- el Stop de RADIUS/lease de DHCP.
    ended_at     DateTime('UTC') DEFAULT toDateTime(4294967295),
    source       Enum8('static' = 1, 'file' = 2, 'radius' = 3, 'dhcp' = 4, 'manual' = 5) DEFAULT 'radius',
    nas_id       LowCardinality(String) DEFAULT '',
    username     String DEFAULT '',
    updated_at   DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(started_at)
ORDER BY (ip, started_at)
TTL started_at + INTERVAL 180 DAY;
