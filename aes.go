package wechat

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
)

//微信小程序用户信息解密
var (
	ErrPaddingSize   = errors.New("padding size error")
	ErrAppIDNotMatch = errors.New("appId not match")
)

type UserInfo struct {
	OpenGId   string `json:"openGId,omitempty"`
	OpenID    string `json:"openId"`
	UnionID   string `json:"unionId"`
	NickName  string `json:"nickName"`
	Gender    int    `json:"gender"`
	City      string `json:"city"`
	Province  string `json:"province"`
	Country   string `json:"country"`
	AvatarURL string `json:"avatarUrl"`
	Language  string `json:"language"`
	Watermark struct {
		Timestamp int64  `json:"timestamp"`
		AppID     string `json:"appid"`
	} `json:"watermark"`
}

type WXConfig struct {
	appID, sessionKey string
}

func NewWXConfig(appID, sessionKey string) *WXConfig {
	return &WXConfig{
		appID:      appID,
		sessionKey: sessionKey,
	}
}

// 接口返回的加密数据( encryptedData )进行对称解密。 解密算法如下：
// 对称解密使用的算法为 AES-128-CBC，数据采用PKCS#7填充。
// 对称解密的目标密文为 Base64_Decode(encryptedData)。
// 对称解密秘钥 aeskey = Base64_Decode(session_key), aeskey 是16字节。
// 对称解密算法初始向量 为Base64_Decode(iv)，其中iv由数据接口返回。
// AES并没有64位的块, 如果采用PKCS5, 那么实质上就是采用PKCS7
func (w *WXConfig) Decrypt(encryptedData, iv string) (*UserInfo, error) {
	aesKey, err := base64.StdEncoding.DecodeString(w.sessionKey)
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	ivBytes, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(cipherText))
	cipher.NewCBCDecrypter(block, ivBytes).CryptBlocks(plaintext, cipherText)
	plaintext, err = PKCS5UnPadding(plaintext, block.BlockSize())

	var userInfo UserInfo
	err = json.Unmarshal(plaintext, &userInfo)
	if err != nil {
		return nil, err
	}
	if userInfo.Watermark.AppID != w.appID {
		return nil, ErrAppIDNotMatch
	}
	return &userInfo, nil
}

func PKCS5UnPadding(plaintext []byte, blockSize int) ([]byte, error) {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	if unpadding >= length || unpadding > blockSize {
		return nil, ErrPaddingSize
	}
	return plaintext[:(length - unpadding)], nil
}
