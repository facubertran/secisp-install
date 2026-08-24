// Package jobssql embebe los SQL de los ocho jobs de baselining de E09
// (T-327/T-328: "el SQL de cada job se carga con go:embed... y no por
// secisp schema apply"). Vive acá, no en internal/detect/anomaly/jobs, por
// la misma razón que deploy/clickhouse/embed.go documenta: //go:embed
// resuelve sus patrones relativos al directorio del archivo fuente y no
// puede atravesar el directorio padre ni referenciar un directorio hermano
// ("pattern ../file: invalid pattern syntax") -- deploy/clickhouse/jobs/
// es hermano de internal/, así que la única forma de que el binario
// incorpore este árbol sin copiarlo es declarar el embed adentro de él.
//
// internal/detect/anomaly/jobs importa este paquete directamente: no hay
// un re-export vía internal/chdb, a diferencia de deploy/clickhouse/embed.go
// (internal/chdb.DDL) -- chdb.DDL es específicamente el instalador de
// esquema, y estos archivos deliberadamente NO pasan por
// `secisp schema apply` (T-328).
//
// Cada job tiene su propio archivo embed_<job>.go con su propia variable
// (uno por task de la ola, T-329..T-336): un solo embed.go compartido
// obligaría a que cada task tocara el mismo archivo.
package jobssql

import _ "embed"

//go:embed bl_cohorts.sql
var Cohorts string
