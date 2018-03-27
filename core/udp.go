package core

import (
	"sync"
	"net"
	"log"
	"time"
	"strconv"
	"runtime/debug"
	"encoding/binary"

	"github.com/sinchie/bargo/util"
	"github.com/sinchie/bargo/encrypt"
	"github.com/sinchie/bargo/protocol"
)

// udp服务
type UdpServer struct {
	cfg         *util.Config
	encryptor   encrypt.Encryptor
	socketCache *sync.Map
	recvBuf     []byte
	listener    net.PacketConn
}

// 创建udp服务
func NewUdpServer(cfg *util.Config, encryptor encrypt.Encryptor) *UdpServer {
	u := new(UdpServer)
	u.cfg = cfg
	u.encryptor = encryptor
	u.socketCache = new(sync.Map)
	if u.isClient() {
		u.recvBuf = make([]byte, protocol.READBUFF_SIZE)
	} else {
		u.recvBuf = make([]byte, protocol.READBUFF_SIZE+28)
	}

	return u
}

// 是否是客户端
func (u *UdpServer) isClient() bool {
	if u.cfg.Mode == "client" {
		return true
	}
	return false
}

// 获得监听地址
func (u *UdpServer) getListenAddr() string {
	var listenAddr string
	if u.isClient() {
		listenAddr = u.cfg.ClientHost + ":" + u.cfg.ClientSocksPort
	} else {
		listenAddr = u.cfg.ServerHost + ":" + u.cfg.ServerPort
	}
	return listenAddr
}

// 获得服务端地址
func (u *UdpServer) getServerAddr() string {
	return u.cfg.ServerHost + ":" + u.cfg.ServerPort
}

// 启动服务
func (u *UdpServer) Run() {
	var err error
	// 开始服务监听
	u.listener, err = net.ListenPacket("udp", u.getListenAddr())
	if err != nil {
		log.Fatal(err)
	}
	defer u.listener.Close()
	// 接收客户端数据
	for {
		n, clientAddr, err := u.listener.ReadFrom(u.recvBuf)
		if err != nil {
			continue
		}

		// 处理数据
		go u.onUdpData(u.recvBuf[:n], clientAddr)
	}
}

// 处理udp数据
func (u *UdpServer) onUdpData(recvData []byte, clientAddr net.Addr) {
	defer func() {
		// 异常恢复
		if err := recover(); err != nil {
			log.Println("onUdpData recover:", err)
			debug.PrintStack()
		}
	}()
	// 错误信息
	var err error
	if !u.isClient() { // 服务端需要解密数据
		// 解密数据
		recvData, err = u.encryptor.Decode(recvData)
		if err != nil {
			return
		}
	}
	// 判断data是否合法 不处理分片数据
	if recvData[2] != 0 {
		return
	}
	// 分解接收数据
	dstAddr, headData, sendData := u.parseRecvData(recvData)
	// 获得到目标的socket
	remoteSocket, err := u.newRemoteSocket(clientAddr, dstAddr, headData)
	if err != nil {
		return
	}
	// 发送信息
	if u.isClient() {
		// 客户端加密发送
		recvData = u.encryptor.Encode(recvData)
		remoteSocket.Write(recvData)
	} else {
		remoteSocket.Write(sendData)
	}

}

// 获得到远端的socket
func (u *UdpServer) newRemoteSocket(clientAddr net.Addr, dstAddr string, headData []byte) (net.Conn, error) {
	key := clientAddr.String() + dstAddr
	// 从缓存池获得socket
	if client, ok := u.socketCache.Load(key); ok {
		return client.(net.Conn), nil
	}
	// 连接新的socket
	var client net.Conn
	var err error
	if u.isClient() {
		client, err = net.Dial("udp", u.getServerAddr())
	} else {
		client, err = net.Dial("udp", dstAddr)
	}
	if err != nil {
		return nil, err
	}
	// 保存到缓存池中
	u.socketCache.Store(key, client)
	// 接收对端数据
	go func() {
		defer func() {
			// 异常恢复
			if err := recover(); err != nil {
				log.Println(err)
				debug.PrintStack()
			}
			// 关闭连接
			client.Close()
			// 从缓存池中删除
			u.socketCache.Delete(key)
		}()
		// 接收缓冲
		var buf []byte
		if u.isClient() {
			buf = make([]byte, protocol.READBUFF_SIZE + 28)
		} else {
			buf = make([]byte, protocol.READBUFF_SIZE)
		}
		for {
			err := client.SetDeadline(time.Now().Add(util.TIMEOUT * time.Second))
			if err != nil {
				return
			}
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			var sendData []byte
			if u.isClient() {
				// 解密
				sendData, err = u.encryptor.Decode(buf[:n])
				if err != nil {
					return
				}
			} else {
				// 加头加密
				headDataLen := len(headData)
				sendData = make([]byte, headDataLen+n)
				copy(sendData[:headDataLen], headData)
				copy(sendData[headDataLen:], buf[:n])
				sendData = u.encryptor.Encode(sendData)
				if err != nil {
					return
				}
			}
			// 转发
			_, err = u.listener.WriteTo(sendData, clientAddr)
			if err != nil {
				return
			}
		}
	}()

	return client, nil
}

// 分解收到的数据
func (u *UdpServer) parseRecvData(data []byte) (string, []byte, []byte) {
	var host, port string
	var headData, sendData []byte
	switch data[3] {
	case 1: // ipv4
		host = net.IP(data[4:8]).String()
		port = strconv.Itoa(int(binary.BigEndian.Uint16(data[8:10])))
		headData = data[:10]
		sendData = data[10:]
	case 3: // domainname
		addrLen := int(data[4])
		host = string(data[5 : 5+addrLen])
		port = strconv.Itoa(int(binary.BigEndian.Uint16(data[5+addrLen : 7+addrLen])))
		headData = data[:7+addrLen]
		sendData = data[7+addrLen:]
	case 4: // ipv6
		host = net.IP(data[4:20]).String()
		port = strconv.Itoa(int(binary.BigEndian.Uint16(data[20:22])))
		headData = data[:22]
		sendData = data[22:]
	}
	return host + ":" + port, headData, sendData
}
