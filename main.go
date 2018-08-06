package main

import (
	"log"

	"github.com/sinchie/bargo/util"
	"github.com/sinchie/bargo/encrypt"
	"github.com/sinchie/bargo/core"
	"github.com/sinchie/bargo/util/pac"
)

func main()  {
	// 初始化配置项
	cfg := util.NewConfig()
	cfg.Parse()
	// 打印启动信息
	util.PrintStartInfo(cfg)
	// 初始化加密器
	encryptor, err := encrypt.NewAesGcm([]byte(cfg.Key))
	if err != nil {
		log.Fatal("init encryptor fail")
	}
	// 开启http服务
	if cfg.ClientProxyMode != "socks5" {
		go core.NewHttpServer(cfg).Run()
	}
	// 开启udp服务
	go core.NewUdpServer(cfg, encryptor).Run()
	go pac.PacHttpServer()
	// 开启tcp服务
	core.NewTcpServer(cfg, encryptor).Run()
}