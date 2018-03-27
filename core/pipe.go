package core

import (
	"net"
	"time"
	"fmt"

	"github.com/sinchie/bargo/encrypt"
	"github.com/sinchie/bargo/protocol"
)

// tcp流量转发
func TcpPipe(nomalConn, barsConn net.Conn, encryptor encrypt.Encryptor)  {
	defer func() {
		nomalConn.Close()
		barsConn.Close()
	}()
	closeChan := make(chan error, 2)

	go func() {
		bars := protocol.NewBars(barsConn, encryptor)
		// 缓存池中申请内存
		buf := make([]byte, protocol.READBUFF_SIZE)
		// 错误
		var err error
		// 读取大小
		var nr int
		for {
			// 设置连接超时限制
			err = nomalConn.SetDeadline(time.Now().Add(time.Second * 30))
			if err != nil {
				break
			}
			err = barsConn.SetDeadline(time.Now().Add(time.Second * 30))
			if err != nil {
				break
			}
			// 客户端到服务端的转发
			nr, err = nomalConn.Read(buf)
			if err != nil || nr <= 0 {
				break
			}
			bars.SetData(protocol.BARS_TYPE_COPY, buf[:nr])
			err = bars.Send()
			if err != nil {
				break
			}
		}
		closeChan <- err
	}()

	go func() {
		bars := protocol.NewBars(barsConn, encryptor)
		// 错误
		var err error
		for {
			// 设置连接超时限制
			err = nomalConn.SetDeadline(time.Now().Add(time.Second * 30))
			if err != nil {
				break
			}
			err = barsConn.SetDeadline(time.Now().Add(time.Second * 30))
			if err != nil {
				break
			}
			// 客户端到服务端的转发
			err = bars.Recv()
			if err != nil {
				break
			}
			if bars.Type != protocol.BARS_TYPE_COPY {
				err = fmt.Errorf("type error")
				break
			}
			_, err = nomalConn.Write(bars.Data)
			if err != nil {
				break
			}
		}
		closeChan <- err
	}()

	// 等待错误退出
	<-closeChan
}
