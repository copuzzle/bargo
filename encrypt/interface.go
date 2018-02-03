package encrypt

// 加密接口
type Encryptor interface {
	// 加密
	Encode([]byte) ([]byte, error)
	// 解密
	Decode([]byte) ([]byte, error)
}
