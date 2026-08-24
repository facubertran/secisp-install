-- 05_dim_net_prefixes.sql [E04]
--
-- T-063 (E04-T08) -- E04 §4.1.1, §4.1.2 · E00b D-16 · E00e G-2 · E03 §4.9.1.
--
-- Fuente de verdad de runtime del scope de red (D1: una sola tabla con
-- `scope`, no dos listas de semántica sobrecargada -- allow_src_nets /
-- ignore_nets del prototipo). La consume dict_net_prefixes (08_dict.sql, un
-- archivo más adelante en el layout) leyendo la vista _v6 de abajo. Ninguna
-- MV de ingesta toca esta tabla ni el diccionario que la envuelve
-- (E00 ADR-008): una falla acá degrada la detección, nunca la ingesta.
--
-- TRAMPA CENTRAL (D-N2, el bug real del prototipo). `is_enabled` NO
-- participa de la ORDER BY. Si estuviera -- por ejemplo
-- `ORDER BY (is_enabled, prefix)`, como en `allow_src_nets` del prototipo --
-- la fila habilitada y la deshabilitada de un mismo prefijo serían dos
-- claves DISTINTAS para ReplacingMergeTree y coexistirían para siempre: un
-- INSERT con is_enabled=0 no reemplazaría nada, sumaría una fila más, y
-- "desactivar" una exclusión no la desactivaría -- en silencio, sin una sola
-- línea de error. Con `ORDER BY (prefix)` a secas, el INSERT nuevo cae en la
-- MISMA clave que la fila vieja y la reemplaza en el próximo merge (o de
-- inmediato para quien lee con FINAL): E04-01 verifica exactamente esto.

CREATE TABLE IF NOT EXISTS isp.dim_net_prefixes
(
    -- Prefijo tal como lo escribe el humano: '203.0.113.0/24' o '2001:db8::/32'.
    -- Se normaliza a forma canónica (bits de host en cero) al aplicar
    -- (E04 §4.4, V01). NO se guarda en forma IPv4-mapped acá: eso lo hace la
    -- vista _v6 de abajo, para que la tabla siga siendo legible por un humano.
    prefix          String,

    -- Lado de la red. Mismos valores numéricos que flows_raw.src_scope (E00 §4.1.2).
    --   customer = prefijo de un cliente del ISP -> es el que puede ser atacante.
    --   infra    = infraestructura propia (pool de NAT, DNS, MX, caché de CDN,
    --              monitoreo, transporte). El pool de NAT se declara igual
    --              aunque nunca aparezca como src_ip (E04 §4.1.4).
    --   external = todo lo demás. Se declara explícitamente SOLO para
    --              excepciones dentro de un bloque customer/infra, o para
    --              colgarle un ignore_*.
    scope           Enum8('unknown'=0, 'customer'=1, 'infra'=2, 'external'=3) DEFAULT 'customer',

    -- Identidad estable del abonado dueño del prefijo. '' = desconocido.
    -- Es el fallback cuando no hay resolver dinámico (E04 §4.8).
    customer_id     LowCardinality(String) DEFAULT '',

    -- Exclusiones. NO filtran la ingesta (E04 D3): las consumen E05 (WHERE
    -- del detector) y E11 (red de seguridad antes de tocar el router).
    ignore_src      UInt8 DEFAULT 0,   -- no detectar cuando esta IP es el ORIGEN
    ignore_dst      UInt8 DEFAULT 0,   -- no accionar cuando esta IP es el DESTINO

    label           String DEFAULT '',                  -- texto libre para el humano y el panel
    owner           LowCardinality(String) DEFAULT '',  -- quién es responsable de la fila
    -- Vencimiento de la fila (D-N1): una exclusión temporal deja de aplicar
    -- sola. '1970-01-01' (default) = sin vencimiento.
    expires_at      DateTime('UTC') DEFAULT toDateTime(0),

    is_enabled      UInt8 DEFAULT 1,             -- borrado lógico, nunca DELETE
    created_at      DateTime('UTC') DEFAULT now(),
    updated_at      DateTime64(3,'UTC') DEFAULT now64(3),
    updated_by      LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (prefix)
SETTINGS index_granularity = 8192;

-- dim_net_prefixes_v6 -- SIN el prefijo `v_` (E04 §4.1.2): es la ÚNICA
-- excepción deliberada a la convención de nombres del sistema. E00 fijó
-- literalmente `SOURCE(CLICKHOUSE(TABLE 'dim_net_prefixes_v6' DB 'isp'))` en
-- el DDL del diccionario; renombrar la vista para que cumpla la convención
-- sería una enmienda a E00, no una transcripción, y el diccionario dejaría
-- de encontrar su fuente.
--
-- Toda lectura de dim_net_prefixes pasa por `FINAL` (arriba en el CREATE
-- TABLE no hace falta un índice extra: el filtro real vive acá) o por esta
-- vista, que ya lo hace.
CREATE OR REPLACE VIEW isp.dim_net_prefixes_v6 AS
SELECT
    -- Conversión a forma IPv4-mapped, obligatoria por E00 §4.1.1:
    --   a.b.c.d/L  ->  ::ffff:a.b.c.d/(96+L)
    --   p/L (v6)   ->  sin cambios
    -- El diccionario IP_TRIE acepta el prefijo como String; la clave que se
    -- le consulta después es toIPv6(ip), y las dos familias caen en el mismo
    -- árbol.
    if(position(prefix, ':') > 0,
       prefix,
       concat('::ffff:',
              splitByChar('/', prefix)[1],
              '/',
              toString(96 + toUInt16(splitByChar('/', prefix)[2])))
    ) AS prefix,
    toUInt8(scope)          AS scope,
    customer_id,
    ignore_src,
    ignore_dst,
    label
FROM isp.dim_net_prefixes FINAL
WHERE is_enabled = 1
  -- Vencimiento: una fila vencida deja de aplicar sin que nadie la toque (D-N1).
  AND (expires_at = toDateTime(0) OR expires_at > now());
