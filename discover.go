package definger

import (
	"fmt"
	"gitee.com/menciis/logx"
	"github.com/k0kubun/pp/v3"
	"net"
)

var DefaultHeader = map[string]string{
	"Accept-Language": "zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6",
	"User-agent":      "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36",
	"Cookie":          "rememberMe=int",
}

type DefineResult struct {
	Title        string   `json:"title,omitempty"`
	Host         string   `json:"host,omitempty"`
	Port         string   `json:"port,omitempty"`
	Path         string   `json:"path,omitempty"`
	Url          string   `json:"url,omitempty"`
	Protocol     string   `json:"protocol,omitempty" #:"协议"`
	IdentifyInfo string   `json:"identify_info,omitempty" #:"指纹信息"`
	Technologies []string `json:"technologies,omitempty" `
}

type DefineCert struct {
	Subject            string   `json:"subject" #:"主体"`
	DomainName         string   `json:"domainName" #:"域名"`
	SignatureAlgorithm string   `json:"signature_algorithm" #:"签名哈希算法"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm" #:"公钥加密算法"`
	Issuer             string   `json:"issuer" #:"颁发者"`
	SANs               []string `json:"sans"`
	NotBefore          string   `json:"notBefore" #:"开始时间(UTC)"`
	NotAfter           string   `json:"notAfter" #:"结束时间(UTC)"`
}

func NewDefineResult(host string, port string, pt string) *DefineResult {
	c := &DefineResult{
		Protocol:     pt, //http, https
		Host:         host,
		Port:         port,
		IdentifyInfo: "None", //状态码
	}
	return c
}

func (d *DefineResult) HttpIdentifyResult() {
	var timeout = 3
	var targetUrl string
	targetUrl = d.getTargetUrl(d.Host, d.Port)
	r, err := identify(targetUrl, timeout)
	if err != nil {
		logx.Error(err)
	}
	for _, results := range r {
		d.IdentifyInfo = results.Result
		d.Url = results.Url
		d.Title = results.Title
		d.Technologies = results.Technologies
	}

}

func (d *DefineResult) getTargetUrl(host string, port string) string {
	//if hubur.IsIP(host) && hubur.IsIPv6(host) {
	//	host = fmt.Sprintf("[%v]", host)
	//}
	if port == "80" {
		return fmt.Sprintf("http://%v", net.JoinHostPort(host, port))
	} else if port == "443" || port == "8443" || port == "10000" {
		return fmt.Sprintf("https://%v", net.JoinHostPort(host, port))
	} else {
		return fmt.Sprintf("http://%v", net.JoinHostPort(host, port))
	}
}

func (d *DefineResult) Print() {
	pp.Println(d)
}
