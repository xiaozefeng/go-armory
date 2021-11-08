package rsautil

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pri, err := GenerateKey(2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pri = %+v\n", pri)

	content := "hello world"
	signAndVerify(pri, &pri.PublicKey, content)
}

func signAndVerify(pri *rsa.PrivateKey, pub *rsa.PublicKey, content string) {
	sign, err := SignPKCS1v15([]byte(content), pri)
	if err != nil {
		log.Fatal(err)
	}
	err = VerifyPKCS1v15([]byte(content), sign, &pri.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

}

func TestGenerateKey(t *testing.T) {
	privateKey, err := GenerateKey(2048)
	if err != nil {
		log.Fatal(err)
	}
	privateBytes := PrivateKeyToBytes(privateKey)
	fmt.Printf("%s\n", privateBytes)
	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(privateBytes))
	publicKey, err := PublicKeyToBytes(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", publicKey)
	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(publicKey))
}

func TestBytesToKeyAndCheck(t *testing.T) {
	var privateKeyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0q2TBd3UDeFs9maZYPMrqXKQHa2bmkpfHjKZGl3yJTiW5jqh
Um3uK8AB66EO1y0uWsSiycxu+xSwJh3xQZ3/D5a8SZEhzfnVfxgsgpoG3MgrtnPr
K4AF3lv867lxOesY/9OpBYcXY/jGsLvUx4kfvevhWnxeQR4ZpU46wkTnoaAN8sti
bFF3xBBkFnhgDlBSa5yQYExIp9aVETOj7fcqWNXfNhQwpOZU0oJ3MqCmoyVnbFWR
Rn12hMU7sagRu5wROJLZ3Lr9ejmRTzy8gnPGnIUWhWt2CQ5lOUruFfz2uWUFve+1
6y96TBU6ucD4PLWWuEozg4BxI74+qnEvemPvBQIDAQABAoIBADV/gjAhLnH/5m2D
jDtERLgYsWP36+V4MUM30g0SAiVVg2wfQ0vtQme1sEcndN9LR9Qgzr2zvhLgJALp
45OoDVbmDhYYVp85a++EMflQJ6H06rTAJt26+sKGVWl+g7QTcRu1odwXe+cVC09h
wxyQQ5E0ztrtbfnXLOf/P4iJetBdoFbntIQWv2DcewZI1WTfFRKBBk5LtNlyRqeb
UC1inpP352PpecV5eCw2WHowOsSQ/WLMqYzyazMLxEtZYXYaEV6vwiiEyNJnJBwS
80tO1/KxWwStxQfqeOrmvfeg0v5y3ZDWcnxUQFoH4a8XRyJgWikosORMtKEWOhnn
dj/n/8ECgYEA89ec6wY2VAg+Qw0aNh1MByhYIFBWqZ03zZ5srP/39xJFRdmq/RQk
u3PIO2ZY3/vVMyKLBionOVCfpJEs2tIgVIOyJvqGwNh6WHopSuGG7iJS3EUHhVkK
hAvCTpXXz/UnTAtTqq85GDO+pDuUre5nkwXLb9YaH9KWIo5DNrmt4F0CgYEA3S6n
yKde/FwchZjsB1W0fTObLyBzGKPQtcKNf3TUd7Br77kAev0IJl+UuERgze7JDU/C
Svh2+KqUS3zvzavOQifkiA3A6DFkTU2w+R21Q4SLTFdUUNWuB+vawO/flLvYIyqg
LUecec+a3GhwEDHyYuyRQPB5iCT21f5QHnslfskCgYAX+8cVXsENNtpY4fsIA42s
zo0McJp1iF8qvEBYK70J8iQaILSuu8J5JYQ2Q3TOYwivROCDtLWy73kkSJsu0qgX
Z/Sn3NBQO3qdJTbWhKQu2/VmcOuyc/WS001DSX22mJhK5HpQOXfWJ5DCupF/IgnR
7in6UAa1xpK5x2BZC55MiQKBgEvkUU/JFg9zL5orkXkm0CpRhcLS2Isw0lE7cz+z
f5+d2jtD+EU7AwvfqfDcDXc7oqK9pkYBIRlLtlx8fu/MLpaGh6SjS3igUfEwYjPo
HKURGpbUNCsUVoWDSOkApW+sUIooexNuSeOF93X/I8x6xtdooqJsoNa1EDj27Ni4
mnH5AoGBANibQaBqgA4PcSBRjZvuSPYgQC5HOuziPrxgFUkxVRZ6km9akxc/OPID
QHS9qfLmjiA1d8VHy+NlAlzMqOJi+wLqWtAklviyehpilpEiCPucuo+MgnafU6H6
XCy/sDOwU+kc8XhiwnzOSzLPQo34KhBnWS1ESaN3zOG1SxZLDrWI
-----END RSA PRIVATE KEY-----`)

	var publicKeyBytes = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0q2TBd3UDeFs9maZYPMr
qXKQHa2bmkpfHjKZGl3yJTiW5jqhUm3uK8AB66EO1y0uWsSiycxu+xSwJh3xQZ3/
D5a8SZEhzfnVfxgsgpoG3MgrtnPrK4AF3lv867lxOesY/9OpBYcXY/jGsLvUx4kf
vevhWnxeQR4ZpU46wkTnoaAN8stibFF3xBBkFnhgDlBSa5yQYExIp9aVETOj7fcq
WNXfNhQwpOZU0oJ3MqCmoyVnbFWRRn12hMU7sagRu5wROJLZ3Lr9ejmRTzy8gnPG
nIUWhWt2CQ5lOUruFfz2uWUFve+16y96TBU6ucD4PLWWuEozg4BxI74+qnEvemPv
BQIDAQAB
-----END RSA PUBLIC KEY-----`)
	pri, err := BytesToPrivateKey(privateKeyBytes)
	if err != nil {
		t.Error(err)
		return
	}
	pub, err := BytesToPublicKey(publicKeyBytes)
	if err != nil {
		t.Error(err)
		return
	}
	signAndVerify(pri, pub, "hello world")
}

func TestEncryptAndDecrypt(t *testing.T) {
	pri, err := GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}
	var content = "hello world"
	ciphertext, err := EncryptWithPublicKey([]byte(content), &pri.PublicKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("ciphertext = %s\n", ciphertext)
	plaintext, err := DecryptWithPrivateKey(ciphertext, pri)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("plaintext = %s\n", plaintext)

}

func TestBase64(t *testing.T) {

	var hashedPrivate = `MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA3E70YMBU2HWnhoE0PVx/SuuI/206V/Pc71354K+P3oLw7vHppoe8ydKqPl3uvPY5QJyXIp1bj5BOiQEon8+qIQIDAQABAkEA1GztBj1tkiogFnmOvXvq4Xqq5l+T2iqx5bxfrF6cApfFbNSEuNIxf8LvyfBu1yBbnMqTj+I4fypsShgaQWvYAQIhAO6D2XOXyeO9H8IDeDZt/clbbyHhN+zgE1uqTqCfFiFRAiEA7HVtG4ywIR6itFK/5TJr1cTO4vug1jonstfwQMsxR9ECIBF64j3heu9Q1fn/DRlYGEhghhWCjvmyNlj6c0a8Qf/xAiEAl+4XTdVGsfEaP9zPebe8+9x5xfRB8oPpUAtZTniAUJECICpyadjjXXqdNHfJ67T+6Wc6HVdZ+8D9/w0722G9Tx7I`
	//var hashedPublic = `MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANxO9GDAVNh1p4aBND1cf0rriP9tOlfz3O9d+eCvj96C8O7x6aaHvMnSqj5d7rz2OUCclyKdW4+QTokBKJ/PqiECAwEAAQ==`

	res, err := base64.StdEncoding.DecodeString(hashedPrivate)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("res = %s\n", res)

}
