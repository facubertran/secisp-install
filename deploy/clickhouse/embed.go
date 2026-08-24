// Package clickhouse embebe el layout completo del instalador de esquema
// (E03 §4.9.1): todos los archivos deploy/clickhouse/*.sql compilados
// adentro del binario secisp, sin lectura de disco en runtime.
//
// Este paquete vive DELIBERADAMENTE acá y no en internal/chdb, que es donde
// E03-T22 (§4.9.1) nombra la directiva `go:embed`: la sintaxis `//go:embed`
// resuelve sus patrones relativos al directorio del archivo fuente y no
// puede atravesar el directorio padre ni referenciar un directorio hermano
// ("pattern ../file: invalid pattern syntax"). deploy/clickhouse/ es hermano
// de internal/, no un subdirectorio, así que la única forma de que el
// binario incorpore este árbol sin copiarlo es declarar el embed en un
// archivo que viva adentro de él. internal/chdb.DDL reexporta este
// filesystem: es la superficie pública que E03-T22 describe.
package clickhouse

import "embed"

//go:embed *.sql
var FS embed.FS
