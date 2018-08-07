package urlsafe

import (
	"net/http"
	"time"
	"math/rand"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"
	"log"
	"crypto/aes"
	"crypto/cipher"	
	"bytes"
	"io/ioutil"
	"strconv"
	"os"
	"fmt"
)

var logger = log.New(os.Stdout, "safeURL", log.Ldate|log.Ltime|log.Lshortfile)
var httpClient = &http.Client{
	Timeout: time.Second * 10,
}
// Header is part of Req
type Header struct {
	AppID int `json:"appid"`
	Timestamp int `json:"timestamp"`
	V string `json:"v"`
	EchoString string `json:"echostr"`
	Sign string `json:"sign"`
	ClientIP int `json:"client_ip"`
}
// Req is http body
type Req struct {
	Header *Header `json:"header"`
	ReqInfos []byte `json:"reqinfo"`
}

// ReqInfo is part of Req
type ReqInfo struct {
	ID int `json:"id"`
	URL string `json:"url"`
	DeviceID string `json:"deviceid"`
	UserAgent string `json:"user_agent"`
	UserIdentify string `json:"user_identify"`
	IDONTKNOW string `json:"temp"`
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// gen rand string
func randString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// SafeQuery is core funcation, 
func SafeQuery(URL string, appID int, appKey string) (string, error) {
	if appID <= 0 {
		return "", fmt.Errorf("appID error:appID is %d", appID)
	}
	header := &Header{
		AppID: appID,
		Timestamp: int(time.Now().Unix()),
		V: "2.0",
		EchoString: randString(16),
		Sign: "",
		ClientIP: 0,
	}
	req := &Req{
		Header: header,
		ReqInfos: nil,
	}
	hash := md5.Sum([]byte(strconv.Itoa(req.Header.Timestamp) + appKey))
	hashS := hex.EncodeToString(hash[:])
	req.Header.Sign = hashS[16:]
	reqInfo := &ReqInfo{
		ID: 0,
		URL: URL,
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36",
		IDONTKNOW: "90739024570367236902340-680-5860279083475890236790574390-5679023490-769245789013745-80-=683450-loahgfoaehgpahfkghqdoprinpodljfgl;d987590kljdhglkeshjgkljdhklhllo;sajpoiuopdsifhgodfijgpoadsjgopdfhijopi",
	}
	reqInfos := make([]*ReqInfo, 1)
	reqInfos[0] = reqInfo
	reqInfoBytes, err := json.Marshal(reqInfos)
	if err != nil {
		return "", err
	}
	req.ReqInfos, err = AESEncrypt(reqInfoBytes, []byte(appKey))
	if err != nil {
		return "", fmt.Errorf("aes enctypt error: %s", err.Error())
	}
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("json marshal error: %s", err.Error())
	}
	response, err := httpClient.Post("http://www.cloud.urlsec.qq.com", "application/json", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("http post error: %s", err.Error())
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("read http body error: %s", err.Error())
	}
	logger.Printf("response body : %s", string(body))
	n, err := base64.StdEncoding.Decode(body, body)
	if err != nil {
		return "", fmt.Errorf("base64 decode response body error: %s", err.Error())
	}
	body, err = AESDecrypt(body[:n], []byte(appKey))
	if err != nil {
		return "", fmt.Errorf("decrypt response body error: %s", err.Error())
	}
	return string(body), nil
}

// PKCS7Padding is padding method
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
    paddingSize := blockSize - len(ciphertext) % blockSize
    padtext := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
    return append(ciphertext, padtext...)
}

// PKCS7UnPadding is unpadding method
func PKCS7UnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}

// AESEncrypt is encrypt method of AES
func AESEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher error: %s", err.Error())
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:16])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}
// AESDecrypt is decrypt method of AES
func AESDecrypt(cryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher error: %s", err.Error())
	}
//	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:16])
	origData := make([]byte, len(cryptedData))
	blockMode.CryptBlocks(origData, cryptedData)
	return PKCS7UnPadding(origData), nil	
}
