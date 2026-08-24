# deploy/routeros/secisp-user.rsc -- T-294 (E11-T22, ola 8), E11 §9 Q6.
#
# Crea el usuario RouterOS dedicado que routers.yaml usa (nunca `admin`):
# grupo con el mínimo que RouterOS permite expresar para "api + escribir
# address-lists + leer reglas de firewall", sin ftp/ssh/telnet/reboot.
#
# ── Límite honesto de esta plantilla ────────────────────────────────────
#
# Q6 (§9) resuelve, tras Q9, que el usuario dedicado "solo necesita permiso
# para /ip/firewall/address-list (escritura) y leer /ip/firewall/filter" --
# pero el sistema de policies de grupo de RouterOS (v6 y v7) es POR MENÚ
# GRANDE (api/read/write/policy/test/password/sniff/sensitive/romon/ftp/
# ssh/telnet/reboot/web/winbox/dude/tikapp/local), no por ruta fina dentro
# de /ip/firewall/*: no existe, en el RouterOS de hoy, una policy nativa que
# distinga "escribir SOLO address-list" de "escribir cualquier cosa bajo
# /ip/firewall". `write` acá habilita más superficie que la ideal (incluye,
# en teoría, poder tocar /ip/firewall/filter también) -- el residuo real es
# que Q9 sigue protegiendo porque NINGÚN código de producción de este
# repo invoca jamás AddRule/RemoveRule (routeros/rules.go, T-279, con test
# propio que lo verifica): un usuario capaz de escribir reglas no significa
# que el software vaya a hacerlo. `write-sensitive` queda afuera a
# propósito (esconde contraseñas de otros servicios en los listados, sin
# relación con lo que este usuario necesita).
#
# Grupo:
/user group add name=secisp-mitigator policy=api,read,write,!ftp,!ssh,!telnet,!reboot,!policy,!password,!sniff,!sensitive,!romon,!web,!winbox,!dude,!tikapp,!local comment="secisp: mitigator, sin ftp/ssh/telnet, T-294"

# Usuario. Cambiá la contraseña ANTES de aplicar este archivo (no la dejes
# como está abajo) y guardala en SEC_MIT_PW_<NOMBRE_EN_MAYUSCULAS_DE_
# routers.yaml> del lado del proceso secisp, NUNCA en este archivo -- E11
# §4.13/§5.7.
/user add name=secisp group=secisp-mitigator password="CAMBIAR-ANTES-DE-APLICAR" comment="secisp: T-294, ver SEC_MIT_PW_* del lado del proceso"

# ── Verificación post-instalación ───────────────────────────────────────
#
# 1. Confirmá que el usuario puede autenticar contra /rest (T-277 lo hace
#    con basic auth sobre TLS, nunca en claro).
# 2. Confirmá que /ip/firewall/address-list add/set/remove funciona con
#    este usuario.
# 3. Confirmá (a mano, una sola vez por router -- SEC-MIT-009 lo vuelve a
#    chequear en cada resync desde el lado del mitigador) que /ip/firewall/
#    filter print funciona en modo lectura con este usuario.
