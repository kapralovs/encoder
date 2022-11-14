package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const SECRET_KEY = "d25232f4eaac1d03f298c448f97799f7888db5175f1c99e8ef50d7354cbb43ad"

func EncryptAES(data string) (string, error) {
	key := SECRET_KEY
	keyByte, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	plaintext := []byte(data)

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

func DecryptAES(encryptedString string) (string, error) {
	key := SECRET_KEY
	keyByte, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	enc, _ := hex.DecodeString(encryptedString)

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()

	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s", plaintext), nil
}

func main() {
	fmt.Println("Введите 1 для шифровки. 2 для расшифровки: ")
	var flag int
	fmt.Scan(&flag)
	if flag == 1 {
		fmt.Println("Шифровка!")
		fmt.Println("Введите данные: ")
		var data string
		fmt.Scan(&data)
		encryptStr, err := EncryptAES(data)
		if err != nil {
			fmt.Println("Ошибка ", err)
			return
		}
		fmt.Println("Шифрованные данные: ", encryptStr)
	} else {
		fmt.Println("Расшифровка!")
		fmt.Println("Введите данные: ")
		var data string
		fmt.Scan(&data)
		rawStr, err := DecryptAES(data)
		if err != nil {
			fmt.Println("Ошибка ", err)
			return
		}
		fmt.Println("Шифрованные данные: ", rawStr)
	}
}
