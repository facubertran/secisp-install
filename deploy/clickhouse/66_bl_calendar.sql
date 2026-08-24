-- 66_bl_calendar.sql [E09]
--
-- T-076 (E09-T04) -- E09 §5.1, §5.2 · E00b D-13 · E00e G-1 · E09 §4.5.
-- Semilla de T-077 (E09-T05) -- E09 §4.5 · E09 §9.2 Q-E09-3.
--
-- Tipo de día por fecha, para resolver `slot(t) = daytype*24 + hora_local`
-- (E09 §4.5). Sin la tabla, o para una fecha ausente, el sistema degrada a
-- sábado/domingo por `toDayOfWeek`, que es lo razonable (E09 §4.5, §9.2
-- Q-E09-3).

CREATE TABLE IF NOT EXISTS isp.bl_calendar
(
    day        Date,
    daytype    Enum8('laborable'=0, 'no_laborable'=1),
    label      String DEFAULT '',
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (day);

CREATE DICTIONARY IF NOT EXISTS isp.dict_bl_calendar
( day Date, daytype UInt8 DEFAULT 0 )
PRIMARY KEY day
SOURCE(CLICKHOUSE(QUERY 'SELECT day, toUInt8(daytype) FROM isp.bl_calendar FINAL'))
LAYOUT(COMPLEX_KEY_HASHED()) LIFETIME(MIN 3600 MAX 7200);

-- Semilla: los ~15 feriados nacionales argentinos de 2026 (año en curso) y
-- 2027 (el siguiente), todos con daytype='no_laborable' (T-077, E09-T05 --
-- E09 §4.5, §9.2 Q-E09-3). Carnaval y Viernes Santo salen de la fecha de
-- Pascua de cada año; San Martín (17/8) y el Día del Respeto a la
-- Diversidad Cultural (12/10) son trasladables al lunes cuando caen martes,
-- miércoles o jueves (Ley 27.399) -- en 2027 los dos caen martes y se
-- trasladan; en 2026 ya caen lunes. El resto son fechas fijas. Un feriado
-- sembrado como 'laborable' por error contamina de falsos positivos ese día
-- en TODA la cohorte 'biz' (Q-E09-3): la tabla se edita a mano y
-- dict_bl_calendar recoge el cambio dentro de su LIFETIME, sin reiniciar
-- nada. Mantenerla año a año es un runbook de E12, no parte de esta task.
INSERT INTO isp.bl_calendar
    (day, daytype, label)
VALUES
    ('2026-01-01', 'no_laborable', 'Año Nuevo'),
    ('2026-02-16', 'no_laborable', 'Carnaval - lunes'),
    ('2026-02-17', 'no_laborable', 'Carnaval - martes'),
    ('2026-03-24', 'no_laborable', 'Día Nacional de la Memoria por la Verdad y la Justicia'),
    ('2026-04-02', 'no_laborable', 'Día del Veterano y de los Caídos en la Guerra de Malvinas'),
    ('2026-04-03', 'no_laborable', 'Viernes Santo'),
    ('2026-05-01', 'no_laborable', 'Día del Trabajador'),
    ('2026-05-25', 'no_laborable', 'Día de la Revolución de Mayo'),
    ('2026-06-17', 'no_laborable', 'Paso a la Inmortalidad del General Martín Miguel de Güemes'),
    ('2026-06-20', 'no_laborable', 'Día de la Bandera'),
    ('2026-07-09', 'no_laborable', 'Día de la Independencia'),
    ('2026-08-17', 'no_laborable', 'Paso a la Inmortalidad del General José de San Martín'),
    ('2026-10-12', 'no_laborable', 'Día del Respeto a la Diversidad Cultural'),
    ('2026-11-20', 'no_laborable', 'Día de la Soberanía Nacional'),
    ('2026-12-08', 'no_laborable', 'Inmaculada Concepción de María'),
    ('2026-12-25', 'no_laborable', 'Navidad'),

    ('2027-01-01', 'no_laborable', 'Año Nuevo'),
    ('2027-02-08', 'no_laborable', 'Carnaval - lunes'),
    ('2027-02-09', 'no_laborable', 'Carnaval - martes'),
    ('2027-03-24', 'no_laborable', 'Día Nacional de la Memoria por la Verdad y la Justicia'),
    ('2027-03-26', 'no_laborable', 'Viernes Santo'),
    ('2027-04-02', 'no_laborable', 'Día del Veterano y de los Caídos en la Guerra de Malvinas'),
    ('2027-05-01', 'no_laborable', 'Día del Trabajador'),
    ('2027-05-25', 'no_laborable', 'Día de la Revolución de Mayo'),
    ('2027-06-17', 'no_laborable', 'Paso a la Inmortalidad del General Martín Miguel de Güemes'),
    ('2027-06-20', 'no_laborable', 'Día de la Bandera'),
    ('2027-07-09', 'no_laborable', 'Día de la Independencia'),
    ('2027-08-16', 'no_laborable', 'Paso a la Inmortalidad del General José de San Martín - trasladado'),
    ('2027-10-11', 'no_laborable', 'Día del Respeto a la Diversidad Cultural - trasladado'),
    ('2027-11-20', 'no_laborable', 'Día de la Soberanía Nacional'),
    ('2027-12-08', 'no_laborable', 'Inmaculada Concepción de María'),
    ('2027-12-25', 'no_laborable', 'Navidad');
