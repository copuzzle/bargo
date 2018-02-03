package protocol

import (
	"net"
	"io"
	"time"
	"fmt"
	"encoding/binary"
	"math/rand"
	crand "crypto/rand"

	"github.com/sinchie/bargo/encrypt"
	"github.com/sinchie/bargo/util"
)

const (
	// 读取大小
	READBUFF_SIZE = 32 * 1024

	// 混淆数据最小长度
	BARS_CONFUSION_MIN = 100
	// 混淆数据最大长度
	BARS_CONFUSION_MAX = 1000

	// 连接
	BARS_TYPE_LINK = 0x01
	// 转发
	BARS_TYPE_COPY = 0x02
)

/**
	Bars协议
	+-------------+------------------+----------------+--------+------+
	| Pack Length | Confusion Length | Confusion Data |  Type  | Data |
	+-------------+------------------+----------------+--------+------+
	|      2      |         2        |       ...      |    1   | ...  |
	+-------------+------------------+----------------+--------+------+
	|                                                 |   encryption  |
	+-------------+------------------+----------------+--------+------+

	o Pack Length: 数据包总长度 不包含本身（小端序）
	o Confusion Length: 混淆数据长度 不包含本身（小端序）
	o Confusion Data: 混淆数据内容 后面的数据都是加密过的密文
	o Type: 数据类型
	o Data: 荷载数据
*/
type Bars struct {
	PackLength      uint16
	ConfusionLength uint16
	ConfusionData   []byte
	Type            uint8
	Data            []byte
}

// 设置混淆数据
func (b *Bars) setConfusion() error {
	// 混淆长度
	b.ConfusionLength = uint16(BARS_CONFUSION_MIN + rand.Intn(BARS_CONFUSION_MAX-BARS_CONFUSION_MIN))
	// 混淆数据
	b.ConfusionData = make([]byte, b.ConfusionLength)
	_, err := io.ReadFull(crand.Reader, b.ConfusionData)
	if err != nil {
		return err
	}
	return nil
}

// 发送数据包
func (b *Bars) Write(conn net.Conn, encryptor encrypt.Encryptor) error {
	// 生成混淆数据
	err := b.setConfusion()
	if err != nil {
		return err
	}
	// 加密数据
	data := make([]byte, 1 + len(b.Data))
	data[0] = b.Type
	copy(data[1:], b.Data)
	dst, err := encryptor.Encode(data)
	if err != nil {
		return err
	}
	// 计算包长 = 混淆长度位（2） + 混淆数据长度 + 密文长度
	b.PackLength = 2 + b.ConfusionLength + uint16(len(dst))
	// 组合数据
	sendData := make([]byte, 2+b.PackLength)
	binary.LittleEndian.PutUint16(sendData[0:2], b.PackLength)
	binary.LittleEndian.PutUint16(sendData[2:4], b.ConfusionLength)
	copy(sendData[4:b.ConfusionLength+4], b.ConfusionData)
	copy(sendData[b.ConfusionLength+4:], dst)
	// 发送数据
	_, err = conn.Write(sendData)
	if err != nil {
		return err
	}
	// 超时设置
	err = conn.SetDeadline(time.Now().Add(time.Second * util.TIMEOUT))
	if err != nil {
		return err
	}

	return nil
}

// 按照协议解析读取数据包
func (b *Bars) Read(conn net.Conn, encryptor encrypt.Encryptor) (error) {
	// 读取包长度 混淆长度
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	// 超时设置
	err = conn.SetDeadline(time.Now().Add(time.Second * util.TIMEOUT))
	if err != nil {
		return err
	}
	// 包长
	b.PackLength = binary.LittleEndian.Uint16(buf[:2])
	// 包最大长度 = READBUFF_SIZE + BARS_CONFUSION_MAX + 2(混淆长度位) + 28(加密的iv和校验位)
	packMaxLen := uint16(READBUFF_SIZE + BARS_CONFUSION_MAX + 30)
	if b.PackLength > packMaxLen {
		return fmt.Errorf("package too long")
	}
	// 混淆长度
	b.ConfusionLength = binary.LittleEndian.Uint16(buf[2:])
	// 读取包剩余的数据
	buf = make([]byte, b.PackLength-2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	b.ConfusionData = buf[:b.ConfusionLength]
	// 解密数据
	data, err := encryptor.Decode(buf[b.ConfusionLength:])
	if err != nil {
		return err
	}
	b.Type = data[0]
	b.Data = data[1:]

	return nil
}
