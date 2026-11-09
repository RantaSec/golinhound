//go:build linux && arm64

package collect

import _ "embed"

//go:embed embedded_binaries/lssudo-linux-arm64
var lssudoBinary []byte
