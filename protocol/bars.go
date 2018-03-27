package protocol

import (
	"net"
	"io"
	"fmt"
	"encoding/binary"
	"math/rand"
	crand "crypto/rand"

	"github.com/sinchie/bargo/encrypt"
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
	|             |                     encryption                    |
	+-------------+------------------+----------------+--------+------+

	o Pack Length: 数据包总长度 不包含本身（小端序）
	o Confusion Length: 混淆数据长度 不包含本身（小端序）
	o Confusion Data: 混淆数据内容
	o Type: 数据类型
	o Data: 荷载数据
*/
type Bars struct {
	PackLength      uint16
	ConfusionLength uint16
	ConfusionData   []byte
	Type            uint8
	Data            []byte

	encrypt 		encrypt.Encryptor
	conn 			net.Conn
}

// 获得bars
func NewBars(conn net.Conn, encryptor encrypt.Encryptor) *Bars {
	b := new(Bars)
	b.encrypt = encryptor
	b.conn = conn

	return b
}

// 设置数据和类型
func (b *Bars) SetData(typ uint8, data []byte) {
	b.Type = typ
	b.Data = data
}

// 设置混淆数据
func (b *Bars) makeConfusion() {
	// 混淆长度
	b.ConfusionLength = uint16(BARS_CONFUSION_MIN + rand.Intn(BARS_CONFUSION_MAX-BARS_CONFUSION_MIN))
	// 混淆数据
	b.ConfusionData = make([]byte, b.ConfusionLength)
	// 填充
	io.ReadFull(crand.Reader, b.ConfusionData)
}

// 数据打包
func (b *Bars) pack() []byte {
	// 生成混淆数据
	b.makeConfusion()
	// 组合加密数据  混淆长度位(2) + 混淆长度 + type位(1) + 数据长度
	data := make([]byte, 2, 2 + int(b.ConfusionLength) + 1 + len(b.Data))
	binary.LittleEndian.PutUint16(data[:2], b.ConfusionLength)
	data = append(data, b.ConfusionData...)
	data = append(data, b.Type)
	data = append(data, b.Data...)
	// 加密
	dst := b.encrypt.Encode(data)
	// 计算包长
	b.PackLength = uint16(len(dst))
	// 组合数据
	sendData := make([]byte, 2, 2+b.PackLength)
	binary.LittleEndian.PutUint16(sendData[:2], b.PackLength)
	sendData = append(sendData, dst...)

	return sendData
}

// 发送数据包
func (b *Bars) Send() error {
	// 组合数据
	sendData := b.pack()
	// 发送数据
	_, err := b.conn.Write(sendData)
	if err != nil {
		return err
	}

	return nil
}

// 按照协议解析读取数据包
func (b *Bars) Recv() (error) {
	// 读取包长度
	buf := make([]byte, 2)
	_, err := io.ReadFull(b.conn, buf)
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
	// 读取包数据
	buf = make([]byte, b.PackLength)
	_, err = io.ReadFull(b.conn, buf)
	if err != nil {
		return err
	}
	// 解密数据
	data, err := b.encrypt.Decode(buf)
	if err != nil {
		return err
	}
	// 混淆长度
	b.ConfusionLength = binary.LittleEndian.Uint16(data[:2])
	// 类型
	b.Type = data[2+b.ConfusionLength]
	// 内容
	b.Data = data[2+b.ConfusionLength+1:]

	return nil
}
