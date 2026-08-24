-- 41_det_suppress.sql [E05]
--
-- T-073 (E05-T05) -- E05 §5.3 · E00b D-13, D-28.
--
-- D-28: isp.det_suppress_rules es la ÚNICA tabla de supresión de todo el
-- sistema. isp.dim_detect_exceptions -- que E06/E07/E08/E12 llegaron a
-- declarar creyendo que E05 la definía en algún lado -- NO EXISTE: eran dos
-- mecanismos paralelos de excepción y ninguno reconocía al otro. Todos los
-- casos que dim_detect_exceptions resolvía se expresan con las columnas de
-- alcance que esta tabla ya tiene (E05 §5.3.1): resolver DNS del ISP,
-- crawler autorizado, pentest con ventana, sonda de monitoreo, CGNAT no
-- accionable, falso positivo confirmado, MTA declarado.
--
-- isp.ops_audit (donde E05 audita altas/bajas/cambios de estas reglas) NO se
-- declara acá: es de E12 §5.4 (D-36) y vive en 90_ops_audit.sql.

CREATE TABLE IF NOT EXISTS isp.det_suppress_rules
(
    rule_id        UUID,
    rule_name      LowCardinality(String),   -- corto, único, es label de métrica
    enabled        UInt8 DEFAULT 1,
    priority       Int16 DEFAULT 100,        -- menor = se evalúa antes

    -- Alcance. '' / 0 = no filtra por ese eje. Todos los que estén puestos
    -- deben matchear (AND).
    detector_id    LowCardinality(String) DEFAULT '',
    attack_class   LowCardinality(String) DEFAULT '',  -- nombre del enum de E00, '' = cualquiera
    match_src_prefix   String DEFAULT '',    -- CIDR; IPv4 se acepta en forma nativa y se
                                             -- normaliza a ::ffff:a.b.c.d/(96+L) al cargar
    match_customer_id  LowCardinality(String) DEFAULT '',
    match_dst_prefix   String DEFAULT '',
    match_dst_asn      UInt32 DEFAULT 0,
    match_dst_cc       LowCardinality(String) DEFAULT '',
    match_proto        UInt8  DEFAULT 0,
    match_dst_port_min UInt16 DEFAULT 0,
    match_dst_port_max UInt16 DEFAULT 0,     -- 0 = sin tope
    match_max_score    UInt8  DEFAULT 100,   -- solo aplica si score <= este valor

    action         Enum8('suppress'=1, 'downgrade'=2, 'require_corroboration'=3),
    score_delta    Int16 DEFAULT 0,          -- solo action='downgrade'; negativo
    reason         LowCardinality(String),   -- texto corto que va a suppress_reason

    valid_from     DateTime('UTC') DEFAULT toDateTime(0),
    valid_until    DateTime('UTC'),          -- OBLIGATORIO salvo permanent=1
    permanent      UInt8 DEFAULT 0,          -- explícito: una allowlist eterna es una decisión

    created_by     LowCardinality(String),
    created_at     DateTime64(3, 'UTC') DEFAULT now64(3),
    updated_at     DateTime64(3, 'UTC') DEFAULT now64(3),
    notes          String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (rule_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- Semilla: los rule_name de la familia scan (T-251, E06-T21, E06 §5.2, §9 P22)
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Por la regla de propiedad de archivos (../plan/secuencia-de-desarrollo.md
-- §7 bis): T-251 no reclama este archivo como entregable de DDL (es de T-073,
-- E05-T05) -- su entregable es SOLO este bloque INSERT más la convención de
-- priority que documenta.
--
-- Convención de priority de E06 §9 P22 (menor = se evalúa antes, columna
-- `priority` de arriba): cgnat=10, resolver_isp/monitoreo=50,
-- crawler_autorizado/pentest_autorizado=80, falso_positivo_confirmado=90.
-- La intuición: cuanto más ancho y menos supervisado es el match (un /10 de
-- CGNAT entero), antes se evalúa: si dos reglas solapadas empatan en
-- priority, E05 §4.7 desempata por la longitud de match_src_prefix (el
-- prefijo MÁS ESPECÍFICO gana) -- P22 lo deja así de explícito para que dos
-- reglas solapadas no alternen la razón entre recargas (E12 mide O5 sobre
-- suppress_reason, y un número inestable ahí no sirve).
--
-- Los seis rule_name de §5.2, con su match típico:
--
--   resolver_isp (prioridad 50): resolver recursivo del ISP consultando
--     autoritativos (§4.3) -- detector_id='scan.horizontal', match_src_prefix
--     = prefijo del resolver, match_proto=17, match_dst_port_min/max=53.
--   crawler_autorizado (prioridad 80): cliente con un crawler declarado --
--     match_customer_id=<id>, match_dst_port_min=80, match_dst_port_max=443.
--   pentest_autorizado (prioridad 80): pentest contratado, vigencia acotada
--     -- match_customer_id=<id>, attack_class='scan', valid_until = fin de
--     la ventana contratada (nunca permanent=1: un pentest sin fecha de
--     cierre es la forma más lenta de dejar un cliente sin cobertura).
--   monitoreo (prioridad 50): Zabbix/Smokeping de un cliente multi-sede --
--     match_src_prefix, attack_class='scan'.
--   falso_positivo_confirmado (prioridad 90): caso cerrado en la calibración
--     de §8.4 -- el match más específico posible, valid_until acotado.
--   cgnat (prioridad 10, RESERVADO, NO SEMBRADO): P6 responde que no hay
--     CGNAT en este ISP -- sembrar una fila igual sería suprimir tráfico
--     real sin ningún prefijo real que matchear. El rule_name queda
--     reservado como red de seguridad (§4.15: si algún día aparece CGNAT,
--     la fila usa exactamente esta prioridad y esta convención, no una
--     inventada en el momento).
--
-- Las cinco filas de abajo son PLANTILLAS con valores de ejemplo (prefijos
-- RFC 5737, un customer_id inexistente) y enabled=0: un operador las edita
-- con los datos reales de SU deployment (prefijo del resolver, customer_id
-- del crawler/pentest autorizados) y recién ahí las habilita. Sembrarlas ya
-- habilitadas suprimiría tráfico real basado en datos inventados -- exactamente
-- el riesgo que enabled=0 evita, sin dejar de dar un punto de partida
-- descubrible (`SELECT * FROM isp.det_suppress_rules`) en vez de que el
-- operador tenga que escribir el INSERT desde cero. rule_id es un UUID FIJO
-- (no generateUUIDv4()): con ReplacingMergeTree por rule_id, un rule_id
-- aleatorio en cada `schema apply` duplicaría la fila en vez de
-- reemplazarla -- la misma razón por la que 42_dim_detectors.sql versiona
-- por detector_id, una clave estable, no por un UUID nuevo cada vez.
INSERT INTO isp.det_suppress_rules
    (rule_id, rule_name, enabled, priority, detector_id, attack_class,
     match_src_prefix, match_customer_id, match_proto,
     match_dst_port_min, match_dst_port_max,
     action, reason, valid_from, valid_until, permanent,
     created_by, notes)
VALUES
    (toUUID('e06a1000-0000-4000-8000-000000000001'), 'resolver_isp', 0, 50,
     'scan.horizontal', '', '192.0.2.53/32', '', 17, 53, 53,
     'suppress', 'resolver_isp', toDateTime(0), toDateTime(0), 1,
     'seed:T-251',
     'PLANTILLA -- editar match_src_prefix con el /32 (o el rango) real del resolver del ISP y habilitar (enabled=1) antes de usar. E06-H14: con esta fila habilitada, los eventos de scan.horizontal en 53/UDP desde ese prefijo salen con suppressed=1, suppress_reason=''rule:resolver_isp''; los de otro puerto (22, etc.) siguen sin suprimir.'),

    (toUUID('e06a1000-0000-4000-8000-000000000002'), 'crawler_autorizado', 0, 80,
     '', '', '', 'CUST-EXAMPLE', 0, 80, 443,
     'suppress', 'crawler_autorizado', toDateTime(0), toDateTime(0), 1,
     'seed:T-251',
     'PLANTILLA -- editar match_customer_id con el id real del cliente que declaró el crawler y habilitar antes de usar.'),

    (toUUID('e06a1000-0000-4000-8000-000000000003'), 'pentest_autorizado', 0, 80,
     '', 'scan', '', 'CUST-EXAMPLE', 0, 0, 0,
     'suppress', 'pentest_autorizado', toDateTime(0), toDateTime('2099-01-01 00:00:00'), 0,
     'seed:T-251',
     'PLANTILLA -- editar match_customer_id y valid_until con la ventana real del pentest contratado antes de usar. NUNCA permanent=1: un pentest sin fecha de cierre deja al cliente sin cobertura indefinidamente.'),

    (toUUID('e06a1000-0000-4000-8000-000000000004'), 'monitoreo', 0, 50,
     '', 'scan', '198.51.100.0/24', '', 0, 0, 0,
     'suppress', 'monitoreo', toDateTime(0), toDateTime(0), 1,
     'seed:T-251',
     'PLANTILLA -- editar match_src_prefix con los prefijos reales de la sonda Zabbix/Smokeping del cliente multi-sede y habilitar antes de usar.'),

    (toUUID('e06a1000-0000-4000-8000-000000000005'), 'falso_positivo_confirmado', 0, 90,
     '', 'scan', '203.0.113.0/24', 'CUST-EXAMPLE', 0, 0, 0,
     'suppress', 'falso_positivo_confirmado', toDateTime(0), toDateTime('2099-01-01 00:00:00'), 0,
     'seed:T-251',
     'PLANTILLA -- reemplazar por el match MÁS ESPECÍFICO posible del caso cerrado en la calibración de §8.4 (idealmente detector_id + match_src_prefix + match_dst_port_min/max, no solo attack_class) y un valid_until acotado antes de usar.');

-- ═══════════════════════════════════════════════════════════════════════════
-- Semilla: smtp.refused nunca acciona en solitario (T-373, E07-T20, D-33)
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Por la regla de propiedad de archivos (../plan/secuencia-de-desarrollo.md
-- §7 bis): T-373 no reclama este archivo como entregable de DDL (es de T-073,
-- E05-T05) -- su entregable es SOLO este bloque INSERT.
--
-- A diferencia de las cinco plantillas de T-251 (arriba, enabled=0: necesitan
-- datos propios del deployment que solo el operador conoce), esta fila no
-- necesita ningún dato del sitio -- "smtp.refused corrobora antes de accionar"
-- es una política ESTRUCTURAL del detector, no algo que dependa de un
-- prefijo o de un cliente particular. Se siembra habilitada (enabled=1)
-- directamente.
--
-- detector_id='smtp.refused' es el único eje de alcance (los demás quedan en
-- su default '/0, "cualquiera"): un rechazo TCP masivo, solo, nunca prueba
-- abuso -- puede ser un cliente listado por el propio /24 del ISP (D-33,
-- rule:isp_prefix_listed, que NO es una fila de esta tabla: depende de
-- ops_reputation_self + FiredShapeDetectors, datos dinámicos por tick que
-- una fila estática no puede expresar -- ver selflisted.go/refused.go). La
-- etapa 10 de framework.SuppressPipeline (E05 §4.7) lee esta fila para
-- decidir si un Finding de smtp.refused necesita SuppressInput.Corroborated
-- antes de poder accionar; sin corroboración sale suppressed=1,
-- suppress_reason='awaiting_corroboration' (S22); con smtp.small_session o
-- smtp.fanout en la misma ventana, corrobora y acciona (S23); con solo
-- smtp.stalled corrobora igual pero el caso queda con
-- evidence.smtp.weak_corroboration=true (refused.go, weakCorroborationFor).
--
-- permanent=1: D-33 es una corrección estructural, no una excepción con
-- fecha de vencimiento -- un valid_until acá sería reabrir el agujero que
-- esta task cierra.
INSERT INTO isp.det_suppress_rules
    (rule_id, rule_name, enabled, priority, detector_id,
     action, reason, valid_from, valid_until, permanent,
     created_by, notes)
VALUES
    (toUUID('e07a1000-0000-4000-8000-000000000001'), 'smtp_refused_needs_corroboration', 1, 50,
     'smtp.refused',
     'require_corroboration', 'smtp_refused_needs_corroboration', toDateTime(0), toDateTime(0), 1,
     'seed:T-373',
     'D-33: un rechazo TCP masivo, solo, no prueba abuso -- puede ser el propio /24 del ISP listado. Exige que otro detector de smtp.* (small_session, stalled, low_rate, fanout o volume) haya disparado en la misma ventana y el mismo (src_ip, port_class) antes de que smtp.refused pueda accionar. Fila estructural, no una plantilla: no requiere edición.');
