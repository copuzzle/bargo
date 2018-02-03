package util

import (
	"os"
	"log"

	"github.com/getlantern/golog"
	"github.com/getlantern/sysproxy"
)

// 开启系统http代理
func OpenSysproxy(cfg *Config) {
	// 忽略输出
	nul, _ := os.OpenFile(os.DevNull, os.O_APPEND|os.O_RDWR, 0666)
	golog.SetOutputs(nul, nul)
	// 开启代理
	err := sysproxy.EnsureHelperToolPresent("bargo-sysproxy", "Input your password and see the world!", "")
	if err != nil {
		log.Fatal("Error EnsureHelperToolPresent: %s\n", err)
		return
	}
	host := "127.0.0.1"
	if len(cfg.ClientHost) != 0 {
		host = cfg.ClientHost
	}
	_, err = sysproxy.On(host + ":" + cfg.ClientHttpPort)
	if err != nil {
		log.Fatal("Error set proxy: %s\n", err)
		return
	}
}
