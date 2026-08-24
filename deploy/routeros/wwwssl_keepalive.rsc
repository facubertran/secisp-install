# deploy/routeros/wwwssl_keepalive.rsc -- T-294 (E11-T22, ola 8).
#
# Del prototipo (docs/mikrotik/wwwssl_keepalive.rsc, citado en E11 §1.6 M1/
# §7 riesgo "API REST del router 'habilitada pero no bindeada'"): "está bien
# resuelto y no hay por qué rehacerlo" -- se entrega tal cual, en el paquete
# de instalación.
#
# El problema que resuelve: tras un reboot o un upgrade de RouterOS, el
# listener del servicio www-ssl (sobre el que corre la API REST que usa el
# mitigador, T-277) a veces queda "habilitado" en /ip service pero NO
# bindeado en su puerto. El mitigador entonces ve "connection refused" en
# CADA request -- sec_mit_router_up cae a 0, SEC-MIT-001 se emite, y a los
# SEC_MIT_ROUTER_DOWN_ALERT_SECONDS (120) sale la notificación -- pero el
# router en sí sigue reportándose "sano" a cualquier chequeo que solo mire
# /ip service (que dice disabled=no, sin verificar que el socket esté
# escuchando de verdad).
#
# La corrección: alternar el servicio deshabilitado/habilitado fuerza a
# RouterOS a re-bindear el listener. Instalado como script + scheduler,
# corre poco después de cada boot (que es cuando el problema aparece) y
# periódicamente como red de seguridad.

:local svcName "www-ssl"
:local svc [/ip service find name=$svcName]

:if ([:len $svc] = 0) do={
    :log warning ("secisp: wwwssl_keepalive: no existe el servicio " . $svcName . " -- revisar manualmente")
} else={
    :if ([/ip service get $svc disabled] = no) do={
        /ip service disable $svc
        :delay 1s
        /ip service enable $svc
        :log info ("secisp: wwwssl_keepalive: " . $svcName . " re-bindeado")
    }
}

# ── Instalación (una vez, a mano) ───────────────────────────────────────
#
# 1. Pegar el bloque de arriba como script:
#      /system script add name=secisp-wwwssl-keepalive source=[/file get [/file find name="wwwssl_keepalive.rsc"] contents]
#    (o copiar/pegar el cuerpo directo en `/system script add name=... source=...`)
#
# 2. Programarlo: una vez ~2 minutos después de cada boot (start-time
#    startup no alcanza -- el servicio todavía no terminó de inicializar
#    tan temprano) y cada 15 minutos como red de seguridad:
#
#      /system scheduler add name=secisp-wwwssl-keepalive-boot \
#          on-event=secisp-wwwssl-keepalive start-time=startup interval=2m \
#          comment="secisp: corre una vez ~2min post-boot, ver max-runs"
#      /system scheduler set secisp-wwwssl-keepalive-boot max-runs=1 policy=read,write,test
#
#      /system scheduler add name=secisp-wwwssl-keepalive-periodic \
#          on-event=secisp-wwwssl-keepalive interval=15m policy=read,write,test \
#          comment="secisp: red de seguridad periódica"
