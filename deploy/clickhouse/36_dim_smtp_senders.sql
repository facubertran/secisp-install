-- 36_dim_smtp_senders.sql [E07]
--
-- T-070 (E07-T03) -- E07 §5.3 · E07 §D8 · E00b D-28.
--
-- Declara isp.dim_smtp_senders: el MTA/MSA de un cliente que el operador
-- conoce de antemano, con su techo esperado (sesiones/h, fan-out de
-- destinos/h) y su escalation_factor. El instalador solo crea la tabla
-- VACÍA -- no lleva un INSERT propio, a diferencia de 31_dim_amp_ports.sql --
-- porque la semilla acá es por-cliente y arranca desde
-- /etc/secisp/smtp_senders.yaml al levantar el proceso que la usa
-- (internal/detect/smtp.LoadIfEmpty, T-070), no desde un archivo del
-- instalador que es igual en todas las instalaciones.
--
-- NO es una allowlist binaria (Trampa de T-070, D8 taxativo): un MTA
-- declarado se sigue vigilando igual. Lo único que cambia es el techo
-- (max_sessions_per_hour / max_dst_fanout_per_hour) y que, si el origen lo
-- rompe por encima de escalation_factor (10x por defecto), el evento sale
-- IGUAL -- con suppressed=0 y attack_subtype='declared_sender_breach' --
-- porque un MTA declarado y comprometido es el peor caso posible, no el
-- único invisible. La supresión binaria de un origen (allowlist de verdad)
-- vive en isp.det_suppress_rules (E00b D-28: única tabla de supresión de
-- todo el sistema), no acá.
--
-- src_prefix se guarda en forma IPv4-mapped CANÓNICA:
--     a.b.c.d/L (IPv4)  ->  ::ffff:a.b.c.d/(96+L)
--     host suelto       ->  /32 (IPv4, antes del mapeo) o /128 (IPv6)
--     p/L (IPv6 nativo) ->  sin cambio de familia
-- con los bits de host puestos a cero, mismo criterio que V01 de E04 §4.4.
-- internal/detect/smtp.NormalizePrefix (T-070) es el único punto de
-- conversión de este repo; el radix trie en RAM de SenderRegistry
-- (E07 §4.11, fuera de esta task) lee esta columna ya normalizada y resuelve
-- por prefijo más específico.
--
-- Sin dependencia de DDL hacia 90_ops_audit.sql [E12]: MergeTree no tiene FK
-- y este archivo se aplica igual exista o no esa tabla todavía en el layout
-- en construcción. Lo que sí depende, en RUNTIME, es el INSERT que
-- LoadIfEmpty hace hacia isp.ops_audit (E04 §4.10 / E12 §5.4 canónico) por
-- cada fila que siembra desde el YAML -- eso corre después de que
-- `secisp schema apply` terminó el layout completo, nunca durante el apply
-- de este archivo puntual.

CREATE TABLE IF NOT EXISTS isp.dim_smtp_senders
(
    -- Prefijo del cliente, en forma IPv4-mapped canónica: ::ffff:a.b.c.d/(96+L).
    -- Un host suelto es /128. internal/detect/smtp.NormalizePrefix normaliza.
    src_prefix              String,
    customer_id             LowCardinality(String) DEFAULT '',

    -- 1 = el cliente corre un MTA legítimo declarado. Baja el peso de los
    -- boosters pero NO suprime: ver escalation_factor.
    is_mta                  UInt8 DEFAULT 1,
    -- 1 = exceptuado de la política de bloqueo del puerto 25 saliente (§4.8).
    port25_allowed          UInt8 DEFAULT 0,

    -- Techos declarados. 0 = usar el default global del detector.
    max_sessions_per_hour   UInt32 DEFAULT 0,
    max_dst_fanout_per_hour UInt32 DEFAULT 0,

    -- Múltiplo del techo a partir del cual el evento se emite IGUAL, con
    -- suppressed=0 y attack_subtype 'declared_sender_breach'. D8: un MTA
    -- declarado y comprometido es el peor caso, no puede ser el único invisible.
    escalation_factor       Float32 DEFAULT 10.0,

    label                   String DEFAULT '',
    owner                   LowCardinality(String) DEFAULT '',
    ticket                  String DEFAULT '',
    -- Obligatorio en la práctica: E12 reporta semanalmente las filas sin
    -- vencimiento. toDateTime(0) = sin vencimiento (se permite, se audita).
    valid_until             DateTime('UTC') DEFAULT toDateTime(0),
    is_enabled              UInt8 DEFAULT 1,
    created_by              LowCardinality(String) DEFAULT '',
    created_at              DateTime('UTC') DEFAULT now(),
    updated_at              DateTime64(3,'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (src_prefix);
