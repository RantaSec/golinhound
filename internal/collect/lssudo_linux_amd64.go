//go:build linux && amd64

package collect

import _ "embed"

//go:embed embedded_binaries/lssudo-linux-amd64
var lssudoBinary []byte
