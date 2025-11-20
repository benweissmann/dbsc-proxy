package proxy

import (
	"fmt"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
)

func main() {
	config.ParseEnv()
	fmt.Println("Hello world!")
}
