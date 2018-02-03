package util

import (
	"strings"
	"flag"
	"os"
	"fmt"
)

// 配置
type Config struct {
	// 运行模式: server 或 client
	Mode string
	// 通讯密码
	Key string
	// 服务端监听地址
	ServerHost string
	// 服务端端口
	ServerPort string
	// 客户端监听地址
	ClientHost string
	// 客户端socks5服务监听端口
	ClientSocksPort string
	// 客户端http服务监听端口
	ClientHttpPort string

	// 客户端开启代理模式
	// socks5    只开socks5服务
	// http-auto http智能服务
	// http-all  http全局服务
	ClientProxyMode string
	// http智能模式下 不需要代理的域名
	ClientWhiteList string
	// http智能模式下 需要代理的域名
	ClientBlackList string
	// 自动设置系统http代理 支持mac windows linux
	ClientSysproxy string
}

// 初始化配置
func NewConfig() *Config {
	c := new(Config)
	c.set(&c.Mode, "mode", "server", "run mode: server | client")
	c.set(&c.Key, "key", "bargo", "Transmission password")
	c.set(&c.ServerHost, "server-host", "", "Server Host")
	c.set(&c.ServerPort, "server-port", "50088", "Server listen port")
	c.set(&c.ClientHost, "client-host", "", "Client Host")
	c.set(&c.ClientSocksPort, "client-socks-port", "1080", "client listen socks port")
	c.set(&c.ClientHttpPort, "client-http-port", "1081", "client listen http port")
	c.set(&c.ClientProxyMode, "client-proxy-mode", "socks5", "client proxy mode: socks5 | http-all | http-auto")
	c.set(&c.ClientWhiteList, "client-whitelist", "", "client http white list domain or ip, use | split")
	c.set(&c.ClientBlackList, "client-blacklist", "", "client http black list domain or ip, use | split")
	c.set(&c.ClientSysproxy, "client-sysproxy", "on", "http or http-auto mode, set system proxy")

	return c
}

// 设置配置参数
func (c *Config) set(p *string, name, def, useage string) {
	// 优先获取环境变量
	envName := "bargo_" + strings.Replace(name, "-", "_", -1)
	v := os.Getenv(envName)
	if len(v) != 0 {
		def = v
	}

	flag.StringVar(p, name, def, useage)
}

// 校验参数是否合法
func (c *Config) check() error {
	// mode 
	if c.Mode != "server" && c.Mode != "client" {
		return fmt.Errorf("Please input correct mode. server or client")
	}
	// server-host
	if len(c.ServerHost) == 0 && c.Mode == "client" {
		return fmt.Errorf("Please input -server-host")
	}

	return nil
}

// 解析配置项
func (c *Config) Parse() {
	flag.Parse()
	// 检测参数合法
	if err := c.check(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
