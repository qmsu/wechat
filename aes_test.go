package wechat

import (
	"testing"
	"fmt"
)

func TestDecrypt(t *testing.T)  {
	appID := "你自己的appid"
	sessionKey := "sessionKey"
	encryptedData := "fY1qTsdoIbqbdb9HmKH/MRkD2WhuQafi2E1WjhyYDqpJYT6NZ4xWG2O5Rou3aprgrmaUB7C2W5MvZ/gR/SXYruRSWcr321zv5WLO7KRd05obbefZQWYs2JV055ESfhW7MY1ioWJGEgyTm17CcEqiZQ=="
	iv := "GUduZxE7oBuGYCcKAZISSQ=="
	pc := NewWXConfig(appID, sessionKey)
	userInfo, err := pc.Decrypt(encryptedData, iv)
	if err != nil {
		fmt.Println("err is:",err.Error())
	}else {
		fmt.Println("userInfo is:",userInfo)
	}
}