package encrypt

// 加密接口
type Encryptor interface {
	// 加密
	Encode([]byte) ([]byte)
	// 解密
	Decode([]byte) ([]byte, error)
}
