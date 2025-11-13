package definger

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/twmb/murmur3"
	"net/url"
	"strings"
)

func SplitSchemeHostPort(urlPath string) (scheme string, host string, port string, path string, err error) {
	if len(urlPath) == 0 {
		return "", "", "", "", fmt.Errorf("请输入合法的url地址")
	}
	if !strings.Contains(urlPath, "://") {
		return "", "", "", "", fmt.Errorf("请输入合法的url地址")
	}
	u, err := url.Parse(urlPath)
	if err != nil {
		return "", "", "", "", err
	}
	port = "80"
	path = "/"
	if len(u.Scheme) > 0 && u.Scheme == "https" && u.Port() == "" {
		port = "443"
	}
	if len(u.Port()) > 0 {
		port = u.Port()
	}

	if len(u.Path) > 0 {
		path = u.Path
	}
	return u.Scheme, u.Host, port, path, nil
}

func getDefaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return "80"
	}
}

// Mmh3Base64Encode 计算 base64 的值,mmh3 base64 编码，编码后的数据要求每 76 个字符加上换行符。具体原因 RFC 822 文档上有说明。然后 32 位 mmh3 hash
func Mmh3Base64Encode(braw string) string {
	bckd := base64.StdEncoding.EncodeToString([]byte(braw))
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.String()
}

func Mmh3Hash32(raw string) string {
	h32 := murmur3.New32()
	_, _ = h32.Write([]byte(raw))
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}

func ArrayUnique(arr []string) []string {
	size := len(arr)
	result := make([]string, 0, size)
	temp := map[string]struct{}{}
	for i := 0; i < size; i++ {
		if _, ok := temp[arr[i]]; ok != true {
			temp[arr[i]] = struct{}{}
			result = append(result, arr[i])
		}
	}
	return result
}
