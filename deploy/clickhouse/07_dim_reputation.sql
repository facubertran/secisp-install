-- 07_dim_reputation.sql [E04]
--
-- T-064 (E04-T09) -- E04 §4.9.1, §4.9.2 · E00e G-2 · E03 §4.9.1.
--
-- Listas de reputación externa (Spamhaus DROP/EDROP, Team Cymru Bogons,
-- FireHOL level1, abuse.ch Feodo/SSLBL), cargadas offline en bloque -- NUNCA
-- consultas DNSBL por IP a volumen (E04 §4.9.1, motivo (b): a volumen viola
-- los términos de Spamhaus y termina en bloqueo del resolver).
--
-- REGLA DURA (E04 §4.9.2): un cliente NUNCA se bloquea porque su IP aparece
-- acá. Esta tabla solo (1) sube el confidence de un evento ya detectado por
-- tráfico, y (2) alimenta el detector opcional policy.* en modo shadow. Si
-- algún día se bloqueara por estar listado, y estar listado fuera
-- consecuencia de haber sido bloqueado tarde, se arma un lazo de
-- realimentación donde el sistema se justifica solo.
--
-- Alimenta dict_reputation, que crea 08_dict.sql (T-066) -- igual que
-- dim_asn_meta, acá quedan solo la tabla y la vista _v6 (E00e G-2).

CREATE TABLE IF NOT EXISTS isp.dim_reputation
(
    prefix     String,
    list_id    LowCardinality(String),     -- 'spamhaus_drop','cymru_bogons','feodo',...
    category   Enum8('unknown' = 0, 'hijacked' = 1, 'bogon' = 2, 'c2' = 3, 'spam' = 4, 'scanner' = 5, 'tor' = 6) DEFAULT 'unknown',
    confidence Float32 DEFAULT 0.5,        -- lo declara el importador de cada lista
    added_at   DateTime('UTC') DEFAULT now(),
    expires_at DateTime('UTC') DEFAULT toDateTime(0),
    is_enabled UInt8 DEFAULT 1,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (prefix, list_id);

-- dim_reputation_v6 -- IP_TRIE exige clave única por prefijo; a diferencia
-- de dim_asn_v6 (que se queda con UNA fuente por precedencia), acá varias
-- listas pueden matchear el mismo prefijo y las N se colapsan en una sola
-- fila: se queda con la de mayor confidence y concatena los list_id (E04
-- §4.9.2), para no perder "está en Feodo Y en FireHOL" detrás de "está en
-- la que tenga mayor confidence".
--
-- Filtra is_enabled y expires_at ACÁ (no en el diccionario): una fila
-- vencida deja de aplicar sin que nadie la toque, igual que
-- dim_net_prefixes_v6.
CREATE OR REPLACE VIEW isp.dim_reputation_v6 AS
SELECT
    prefix_v6                                   AS prefix,
    arrayStringConcat(groupArray(list_id), ',') AS lists,
    toUInt8(max(category))                      AS category,
    max(confidence)                             AS confidence
FROM
(
    SELECT
        if(position(prefix, ':') > 0, prefix,
           concat('::ffff:', splitByChar('/', prefix)[1], '/',
                  toString(96 + toUInt16(splitByChar('/', prefix)[2])))) AS prefix_v6,
        list_id, category, confidence
    FROM isp.dim_reputation FINAL
    WHERE is_enabled = 1
      AND (expires_at = toDateTime(0) OR expires_at > now())
)
GROUP BY prefix_v6;
