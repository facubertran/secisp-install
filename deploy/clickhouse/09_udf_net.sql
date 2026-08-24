-- 09_udf_net.sql [E04]
--
-- T-066 (E04-T10) -- E04 §4.1.3, §5.2 · E00b D-35 · E00d F-2 · E00e G-5 ·
-- E03 §4.9.1 · E04-22.
--
-- Las cuatro UDF de red que E05/E08/E09/E10/E11 usan en su WHERE: net_scope,
-- net_customer, net_ignored_src, net_ignored_dst. Van ACÁ y no antes: el
-- SELECT de humo de E03 §8.2 ejecuta cada UDF apenas se define, y ejecutarla
-- exige que isp.dict_net_prefixes ya exista -- por eso este archivo es
-- estrictamente posterior a 08_dict.sql (F-2). La cadena completa de
-- dependencia es 05_dim_net_prefixes.sql -> 08_dict.sql -> 09_udf_net.sql, y
-- el orden lexicográfico por bytes del layout la respeta: '0' < '8' < '9'.
--
-- Este bloque es el CUERPO EXACTO de E04 §5.2 / §4.1.3, transcrito carácter
-- por carácter -- las dos secciones del spec son, a propósito, el mismo
-- texto. NO se reescribe ni se "mejora" la forma.
--
-- REGLA SIN EXCEPCIONES (D-35): dict_net_prefixes es LAYOUT(IP_TRIE()), una
-- clave compleja, así que el tercer argumento de dictGet* va SIEMPRE
-- envuelto en tuple(toIPv6(ip)). Escribirlo como `toIPv6(ip)` a secas no
-- compila -- no es un detalle de estilo. Si este archivo faltara,
-- `enrich.IsIgnored(ip, dir)` (E04 §5.3) devolvería reliable=false para
-- siempre: por D9 eso es fail-closed, y por E11 §D11 fail-closed significa
-- que TODO plan de mitigación se saltea con `exclusions_unreliable` -- la
-- mitigación queda muerta sin un solo error visible, indistinguible de "no
-- hay ataques" (E04 §4.1.3).
--
-- Contrato de uso (E04 §5.2): SIEMPRE sobre tablas agregadas o sobre
-- det_events, NUNCA dentro de una MV de ingesta (ADR-008).
--
-- NO se declara acá `net_label`: esa UDF es de E10 (T-080) y vive en
-- 69b_udf_render.sql -- distinta épica dueña, distinto archivo, por la
-- regla de propiedad de §7 bis. Tampoco se declara ninguna UDF sobre
-- dict_asn/dict_asn_meta/dict_reputation: E04 §5.2 solo define estas cuatro,
-- el resto de las épicas consulta esos diccionarios con dictGet directo en
-- su propia query (ver 40_det.sql, 94b_profile_panel.sql).

CREATE FUNCTION IF NOT EXISTS net_scope AS (ip) ->
  dictGetUInt8('isp.dict_net_prefixes', 'scope', tuple(toIPv6(ip)));

CREATE FUNCTION IF NOT EXISTS net_customer AS (ip) ->
  dictGetString('isp.dict_net_prefixes', 'customer_id', tuple(toIPv6(ip)));

CREATE FUNCTION IF NOT EXISTS net_ignored_src AS (ip) ->
  dictGetUInt8('isp.dict_net_prefixes', 'ignore_src', tuple(toIPv6(ip)));

CREATE FUNCTION IF NOT EXISTS net_ignored_dst AS (ip) ->
  dictGetUInt8('isp.dict_net_prefixes', 'ignore_dst', tuple(toIPv6(ip)));
