package core

import (
	"net"
	"log"
	"time"
	"fmt"
	"runtime/debug"

	"github.com/sinchie/bargo/util"
	"github.com/sinchie/bargo/protocol"
	"github.com/sinchie/bargo/encrypt"
)

// tcp服务
type TcpServer struct {
	cfg        *util.Config
	encryptor  encrypt.Encryptor
}

// 创建tcp服务
func NewTcpServer(cfg *util.Config, encryptor encrypt.Encryptor) *TcpServer {
	t := new(TcpServer)
	t.cfg = cfg
	t.encryptor = encryptor
	return t
}

// 是否是客户端
func (t *TcpServer) isClient() bool {
	if t.cfg.Mode == "client" {
		return true
	}
	return false
}

// 获得监听地址
func (t *TcpServer) getListenAddr() string {
	var listenAddr string
	if t.isClient() {
		listenAddr = t.cfg.ClientHost + ":" + t.cfg.ClientSocksPort
	} else {
		listenAddr = t.cfg.ServerHost + ":" + t.cfg.ServerPort
	}
	return listenAddr
}

// tcp服务
func (t *TcpServer) Run() {
	// 监听服务
	l, err := net.Listen("tcp", t.getListenAddr())
	if err != nil {
		log.Fatal(err.Error())
	}
	defer l.Close()

	// Accept 连接
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		go t.onTcpConnection(conn)
	}
}

// 处理tcp连接
func (t *TcpServer) onTcpConnection(conn net.Conn) {
	defer func() {
		// 关闭连接
		conn.Close()
		// 异常恢复
		if err := recover(); err != nil {
			log.Println("onTcpConnection recover:", err)
			debug.PrintStack()
		}
	}()
	// 设置连接超时限制
	err := conn.SetDeadline(time.Now().Add(time.Second * util.TIMEOUT))
	if err != nil {
		return
	}
	// 获得对端连接
	remoteConn, err := t.getRemoteConn(conn)
	if err != nil {
		return
	}
	defer remoteConn.Close()
	// 设置连接超时限制
	err = remoteConn.SetDeadline(time.Now().Add(time.Second * util.TIMEOUT))
	if err != nil {
		return
	}

	// 开始转发
	if t.isClient() {
		TcpPipe(conn, remoteConn, t.encryptor)
	} else {
		TcpPipe(remoteConn, conn, t.encryptor)
	}
}

// 获得对端连接
func (t *TcpServer) getRemoteConn(conn net.Conn) (net.Conn, error) {
	if t.isClient() { // 客户端
		// socks5协议互交
		requestAddr, err := protocol.HandleSocks5Request(t.cfg.ClientSocksPort, conn)
		if err != nil {
			return nil, err
		}
		// 连接到服务端
		remoteConn, err := net.DialTimeout("tcp", t.cfg.ServerHost+":"+t.cfg.ServerPort, time.Second*util.TIMEOUT)
		if err != nil {
			return nil, err
		}
		// 发送请求地址
		bars := protocol.NewBars(remoteConn, t.encryptor)
		bars.SetData(protocol.BARS_TYPE_LINK, []byte(requestAddr))
		err = bars.Send()
		if err != nil {
			return nil, err
		}
		// 响应客户端成功
		err = protocol.ReplySocks5Tcp(conn)
		if err != nil {
			return nil, err
		}
		return remoteConn, err
	} else { // 服务端
		// 读取客户端的request信息
		bars := protocol.NewBars(conn, t.encryptor)
		err := bars.Recv()
		if err != nil {
			return nil, err
		}
		// 第一次请求类型不对 退出
		if bars.Type != protocol.BARS_TYPE_LINK {
			return nil, fmt.Errorf("type error")
		}
		// 目标地址建立连接
		dstConn, err := net.DialTimeout("tcp", string(bars.Data), time.Second*util.TIMEOUT)
		if err != nil {
			return nil, err
		}
		return dstConn, nil
	}
}
