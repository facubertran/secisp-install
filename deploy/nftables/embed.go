// Package nftablestmpl embebe la plantilla de la regla nftables de T-394
// (E12b-T31, E12 §4.17). Vive acá, no en internal/ops/nftables, por la misma
// razón que deploy/clickhouse/embed.go documenta: //go:embed resuelve sus
// patrones relativos al directorio del archivo fuente y no puede atravesar
// el directorio padre ni referenciar un directorio hermano ("pattern
// ../file: invalid pattern syntax") -- deploy/nftables/ es hermano de
// internal/, así que la única forma de que el binario incorpore este
// archivo sin copiarlo es declarar el embed adentro de él.
//
// Nombrado nftablestmpl, no nftables, para no colisionar con el nombre de
// paquete de internal/ops/nftables (mismo criterio que deploy/clickhouse/
// jobs usa "jobssql" en vez de "jobs" para no chocar con
// internal/detect/anomaly/jobs).
package nftablestmpl

import _ "embed"

//go:embed secisp.nft.tmpl
var Template string
