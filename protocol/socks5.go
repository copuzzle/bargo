package protocol

import (
	"net"
	"io"
	"fmt"
	"strconv"
	"encoding/binary"
	"time"
)

const(
	SOCKS5_CMD_TCP = 0x01
	SOCKS5_CMD_UDP = 0x03

	SOCKS5_ATYP_IPV4 = 0x01
	SOCKS5_ATYP_DOMAINNAME = 0x03
	SOCKS5_ATYP_IPV6 = 0x04
)

/**
	socks5协议握手
	客户端发来的数据
   +----+----------+----------+
   |VER | NMETHODS | METHODS  |
   +----+----------+----------+
   | 1  |    1     | 1 to 255 |
   +----+----------+----------+

	返回数据
	+----+--------+
	|VER | METHOD |
	+----+--------+
	| 1  |   1    |
	+----+--------+

	The values currently defined for METHOD are:

          o  X'00' NO AUTHENTICATION REQUIRED
          o  X'01' GSSAPI
          o  X'02' USERNAME/PASSWORD
          o  X'03' to X'7F' IANA ASSIGNED
          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
          o  X'FF' NO ACCEPTABLE METHODS
 */
func handleSocks5Method(conn net.Conn) error {
	// 协商验证方法
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	version := buf[0]
	nmethods := buf[1]
	// version验证 只支持socks5
	if version != 0x05 {
		return err
	}
	// 读取methods
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	// 无需验证
	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		return err
	}

	return nil
}

/**
	处理socks5连接请求
	+----+-----+-------+------+----------+----------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+

	Where:

	  o  VER    protocol version: X'05'
	  o  CMD
		 o  CONNECT X'01'
		 o  BIND X'02'
		 o  UDP ASSOCIATE X'03'
	  o  RSV    RESERVED
	  o  ATYP   address type of following address
		 o  IP V4 address: X'01'
		 o  DOMAINNAME: X'03'
		 o  IP V6 address: X'04'
	  o  DST.ADDR       desired destination address
	  o  DST.PORT desired destination port in network octet
		 order
 */
func HandleSocks5Request(udpPort string, conn net.Conn) (requestAddr string, err error) {
	// socks5协议握手
	err = handleSocks5Method(conn)
	if err != nil {
		return
	}
	// 请求最大长度 = 4个固定byte + 253域名最大长度 + 2个byte端口长度
	buf := make([]byte, 259)
	_, err = io.ReadFull(conn, buf[:4])
	if err != nil {
		return
	}
	cmd := buf[1]
	atyp := buf[3]
	// 判断请求方式
	if cmd != SOCKS5_CMD_TCP && cmd != SOCKS5_CMD_UDP {
		err = fmt.Errorf("only support tcp and udp")
		return
	}
	// udp请求升级处理
	if cmd == SOCKS5_CMD_UDP {
		err = replySocks5Udp(udpPort, conn)
		if err != nil {
			return
		}
	}
	// 根据不同请求地址类型拼合目标结果
	var addr, port string

	switch atyp {
	case SOCKS5_ATYP_IPV4:
		_, err = io.ReadFull(conn, buf[:6])
		if err != nil {
			return
		}
		addr = net.IP(buf[:4]).String()
		port = strconv.Itoa(int(binary.BigEndian.Uint16(buf[4:])))
	case SOCKS5_ATYP_DOMAINNAME:
		_, err = io.ReadFull(conn, buf[:1])
		if err != nil {
			return
		}
		addrLen := int(buf[0])
		_, err = io.ReadFull(conn, buf[:addrLen+2])
		if err != nil {
			return
		}
		addr = string(buf[:addrLen])
		port = strconv.Itoa(int(binary.BigEndian.Uint16(buf[addrLen:])))
	case SOCKS5_ATYP_IPV6:
		_, err = io.ReadFull(conn, buf[:18])
		if err != nil {
			return
		}
		addr = net.IP(buf[:16]).String()
		port = strconv.Itoa(int(binary.BigEndian.Uint16(buf[16:])))
	default:
		err = fmt.Errorf("Bad socks5 request")
		return
	}

	requestAddr = addr + ":" + port
	err = nil
	return
}

/**
	响应socks5请求
	+----+-----+-------+------+----------+----------+
	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address
 */
 // 响应tcp请求
func ReplySocks5Tcp(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return err
	}

	return nil
}

 // 响应udp请求
func replySocks5Udp(udpPort string, tcpConn net.Conn) error {
	toUdp := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00}
	port, _ := strconv.Atoi(udpPort)
	binary.BigEndian.PutUint16(toUdp[8:10], uint16(port))
	// 响应客户端成功
	_, err := tcpConn.Write(toUdp)
	if err != nil {
		return err
	}
	// 保留这个tcp连接
	err = tcpConn.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	// 等待客户端自己关闭
	for {
		_, err = tcpConn.Read([]byte{0})
		if err != nil {
			return err
		}
	}
}
