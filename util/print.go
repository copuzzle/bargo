package util

import "fmt"

// 打印启动信息
func PrintStartInfo(cfg *Config)  {
	if cfg.Mode == "client" {
		printClientInfo(cfg)
	} else {
		printServerInfo(cfg)
	}
}

// 打印客户端启动信息
func printClientInfo(cfg *Config)  {
	fmt.Printf("--------------------------------\n")
	fmt.Printf("Bargo Client Start\n")
	fmt.Printf("%15s: %s\n", "socks5 port", cfg.ClientSocksPort)
	fmt.Printf("%15s: %s\n", "http port", cfg.ClientHttpPort)
	fmt.Printf("%15s: %s\n", "proxy mode", cfg.ClientProxyMode)
	fmt.Printf("%15s: %s\n", "version", BARGO_VERSION)
	fmt.Printf("--------------------------------\n")
}

// 打印服务端启动信息
func printServerInfo(cfg *Config)  {
	fmt.Printf("--------------------------------\n")
	fmt.Printf("Bargo Server Start\n")
	fmt.Printf("%10s: %s\n", "port", cfg.ServerPort)
	fmt.Printf("%10s: %s\n", "key", cfg.Key)
	fmt.Printf("%10s: %s\n", "version", BARGO_VERSION)
	fmt.Printf("--------------------------------\n")
}
