-- 69b_udf_render.sql [E10]
--
-- T-080 (E10-T02) -- E10 §4.2.1, §4.10.1 · E00b D-35 · E00c C-5 · E00d F-2 ·
-- E10 §9.1 Q3.
--
-- Las tres UDFs de render del panel: isp_proto_str, isp_svc_str y net_label.
-- Texto LITERAL de E10 §4.2.1 -- E03 lo transcribe, no lo diseña (§7 bis).
--
-- Va DESPUÉS de 69_dim_services.sql (isp_svc_str hace dictGet sobre
-- dict_service_names, creado ahí) y DESPUÉS de 08_dict.sql (net_label hace
-- dictGet sobre dict_net_prefixes, creado ahí). El orden lexicográfico por
-- BYTES del layout ya lo respeta: '08' < '69' < '69b'.
--
-- Q3 (E10 §9.1, DECIDIDO): net_label es conceptualmente la cuarta UDF de la
-- familia net_* de E04 §5.2, pero E04 todavía no la adoptó -- queda ACÁ,
-- dueña E10, hasta que una task de E04 la mueva explícitamente. NO se
-- duplica en 09_udf_net.sql (E04 ya deja escrito ahí, en su propio archivo,
-- que net_label no es suya todavía): un CREATE FUNCTION IF NOT EXISTS
-- duplicado en dos archivos deja una definición fantasma si algún día
-- difieren, y test/schema/dictget_tuple_test.go verifica que
-- 09_udf_net.sql NO la contenga.
--
-- REGLA DEL tuple() (D-35, corregida por C-5), sin excepciones en este
-- archivo:
--   - net_label -- dict_net_prefixes es IP_TRIE (clave compleja: el prefijo):
--     la clave SIEMPRE va envuelta, tuple(toIPv6(ip)). Sin el tuple() falla
--     con TYPE_MISMATCH/BAD_ARGUMENTS al crear cualquier vista que la llame
--     -- y se llevan puestas las tres vistas centrales del panel
--     (v_attack_events, v_attack_victims, v_attack_pairs_1m).
--   - isp_svc_str -- dict_service_names es COMPLEX_KEY_HASHED con clave
--     (proto, port) que YA es una tupla (C-5): (toUInt8(proto),
--     toUInt16(port)), SIN tuple() extra. Envolverla de más rompe la
--     llamada tan silenciosamente como olvidarla en un IP_TRIE.
--
-- isp_proto_str NO hace dictGet: es un multiIf estático. Lo que no reconoce
-- se muestra como el número de protocolo (toString), nunca como 'unknown'
-- -- un operador prefiere ver "253" y poder buscarlo que un valor opaco.
--
-- isp_svc_str NO inventa nombre: si dict_service_names no tiene la fila
-- (proto, port), 'name' default '' hace que el sufijo quede vacío y el
-- resultado sea solo "puerto/proto".
--
-- Depende de 00_database.sql (isp_ip_str/isp_ip_net, mismo archivo de
-- namespace de render), 08_dict.sql (dict_net_prefixes) y
-- 69_dim_services.sql (dict_service_names).

-- Nombre legible de protocolo IANA. Cubre lo que aparece en la práctica;
-- el resto se muestra como número, que es mejor que 'unknown'.
CREATE FUNCTION IF NOT EXISTS isp_proto_str AS (p) ->
  multiIf(toUInt8(p) = 1,   'icmp',
          toUInt8(p) = 6,   'tcp',
          toUInt8(p) = 17,  'udp',
          toUInt8(p) = 47,  'gre',
          toUInt8(p) = 50,  'esp',
          toUInt8(p) = 58,  'icmpv6',
          toUInt8(p) = 132, 'sctp',
          toString(toUInt8(p)));

-- '25/tcp SMTP', '53/udp DNS', '4444/tcp'.  Sin nombre conocido no inventa nada.
CREATE FUNCTION IF NOT EXISTS isp_svc_str AS (proto, port) ->
  concat(toString(toUInt16(port)), '/', isp_proto_str(proto),
         if(dictGetString('isp.dict_service_names', 'name',
                          (toUInt8(proto), toUInt16(port))) = '',
            '',
            concat(' ', dictGetString('isp.dict_service_names', 'name',
                                      (toUInt8(proto), toUInt16(port))))));

-- Etiqueta del prefijo dueño de la IP ('' si no matchea nada).
-- La clave va en tuple() porque dict_net_prefixes es IP_TRIE (E00b D-35, E00c C-5).
CREATE FUNCTION IF NOT EXISTS net_label AS (ip) ->
  dictGetString('isp.dict_net_prefixes', 'label', tuple(toIPv6(ip)));
