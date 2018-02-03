package encrypt

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/aes"
	"encoding/hex"
	"crypto/rand"
	"fmt"
	"io"
)

// aes加密
type AesGcm struct {
	aead cipher.AEAD
}

// 获得加密实例
func NewAesGcm(key []byte) (*AesGcm, error) {
	// hash 原始秘钥
	md5er := md5.Sum(key)
	hash := []byte(hex.EncodeToString(md5er[:]))
	// 加密块 aes-128效率更好
	block, err := aes.NewCipher(hash[:16])
	if err != nil {
		return nil, err
	}
	// GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	enc := &AesGcm{
		aead: gcm,
	}
	return enc, nil
}

// 加密
func (a *AesGcm) Encode(plaintext []byte) ([]byte, error) {
	// 计算密文长度 = 明文长度 + 随机数长度 + 校验码长度
	cap := len(plaintext) + 12 + 16
	// 获得随机数
	nonce := make([]byte, 12, cap)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	// 生成密文
	dst := a.aead.Seal(nil, nonce, plaintext, nil)
	dst = append(nonce, dst...)
	return dst, nil
}

// 解密
func (a *AesGcm) Decode(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("ciphertext too little")
	}
	// 解密
	dst, err := a.aead.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	if err != nil {
		return nil, err
	}

	return dst, nil
}
