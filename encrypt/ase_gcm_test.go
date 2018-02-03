package encrypt

import "testing"

func TestAesGcm(t *testing.T) {
	// 密码
	key := []byte("password")
	// 明文
	plaintext := "I am sinchie"

	e, err := NewAesGcm(key)
	if err != nil {
		t.Error(err)
	}
	// 加密
	ciphertext, err := e.Encode([]byte(plaintext))
	if err != nil {
		t.Error(err)
	}
	// 解密
	dst, err := e.Decode(ciphertext)
	if err != nil {
		t.Error(err)
	}
	if string(dst) != plaintext {
		t.Error("Decryption result is wrong")
	}
}
