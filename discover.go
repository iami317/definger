package definger

import (
	"fmt"
	"gitee.com/menciis/logx"
	"github.com/k0kubun/pp/v3"
	"strings"
)

var DefaultHeader = map[string]string{
	"Accept-Language":           "zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6",
	"User-Agent":                "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36",
	"Cookie":                    "rememberMe=int",
	"accept":                    "*/*",
	"accept-encoding":           "gzip, deflate",
	"cache-control":             "no-cache",
	"upgrade-insecure-requests": "1",
}

type DefineResult struct {
	Title        string `json:"title,omitempty"`
	Host         string `json:"host,omitempty"`
	Port         string `json:"port,omitempty"`
	Path         string `json:"path,omitempty"`
	Url          string `json:"url,omitempty"`
	Protocol     string `json:"protocol,omitempty" #:"协议"`
	IdentifyInfo string `json:"identify_info,omitempty" #:"指纹信息"`
	FavicoHash   int64  `json:"favico_hash"`
	FavicoMd5    string `json:"favico_md5"`
}

func NewDefineResult(scheme string, host string, port string, path string) *DefineResult {
	c := &DefineResult{
		Protocol:     scheme, //http, https
		Host:         host,
		Port:         port,
		Path:         path,
		IdentifyInfo: "None", //状态码
	}
	return c
}

func (d *DefineResult) HttpIdentifyResult() {
	var timeout = 10
	var targetUrl string
	targetUrl = d.getTargetUrl()
	r, err := identify(targetUrl, timeout)
	if err != nil {
		logx.Error(err)
	}
	for _, results := range r {
		d.IdentifyInfo = results.Result
		d.Url = results.Url
		d.Title = results.Title
		d.FavicoHash = results.FaviconHash
		d.FavicoMd5 = results.FaviconMd5
		if strings.HasPrefix(d.Url, "https") {
			d.Protocol = "https"
		}
	}

}

func (d *DefineResult) getTargetUrl() string {
	return fmt.Sprintf("%v://%v:%v%v", d.Protocol, d.Host, d.Port, d.Path)
}

func (d *DefineResult) Print() {
	pp.Println(d)
}
