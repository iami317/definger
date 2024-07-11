package definger

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/twmb/murmur3"
	"net"
	"net/url"
	"strings"
)

func SplitSchemeHostPort(hostport string) (scheme string, host string, port string, err error) {
	if strings.Contains(hostport, "://") && strings.Contains(hostport, "http") {
		u, err := url.Parse(hostport)
		if err != nil {
			return "", "", "", err
		}
		scheme = u.Scheme
		hostport = u.Host
	} else {
		scheme = "http"
	}

	if !strings.Contains(hostport, ":") {
		return scheme, hostport, getDefaultPort(scheme), nil
	}

	host, port, err = net.SplitHostPort(hostport)
	if err != nil {
		return scheme, "", "", err
	}

	return scheme, host, port, nil
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
