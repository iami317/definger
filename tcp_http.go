package definger

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/dlclark/regexp2"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/spf13/cast"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

func identify(url string, timeout int) ([]IdentifyResult, error) {
	var RespTitle string
	var RespBody string
	var RespHeader string
	var RespCode string
	var FaviconMd5 string
	var FaviconHash int64
	var RequestRule string
	var DefaultRespTitle string
	var DefaultRespBody string
	var DefaultRespHeader string
	var DefaultRespCode string
	var DefaultTarget string
	var DefaultFaviconMd5 string
	var DefaultFaviconHash int64
	var CustomRespTitle string
	var CustomRespBody string
	var CustomRespHeader string
	var CustomRespCode string
	var CustomTarget string
	var CustomFaviconMd5 string
	var CustomFaviconHash int64

	R, err := defaultRequests(url, timeout)
	if err != nil { //如果目标不能连接，要提示错误
		return nil, err
	}
	for _, resp := range R {
		DefaultRespBody = resp.RespBody
		DefaultRespHeader = resp.RespHeader
		DefaultRespCode = resp.RespStatusCode
		DefaultRespTitle = resp.RespTitle
		DefaultTarget = resp.Url
		DefaultFaviconMd5 = resp.faviconMd5
		DefaultFaviconHash = resp.faviconHash
	}

	// 开始识别
	var successType string
	var identifyResult string
	var identifyResultArr []string
	type Identify_Result struct {
		Name string
		Rank int
		Type string
	}
	var IdentifyData []Identify_Result

	wg := &sync.WaitGroup{}
	for _, rule := range RuleData { //循环取出指纹规则
		wg.Add(1)
		go func(rule RuleLab) {
			defer wg.Done()
			if rule.Http.ReqMethod != "" {
				r, err := customRequests(url, timeout, rule.Http.ReqMethod, rule.Http.ReqPath, rule.Http.ReqHeader, rule.Http.ReqBody)
				if err != nil {
					return
				}

				for _, resp := range r {
					CustomRespBody = resp.RespBody
					CustomRespHeader = resp.RespHeader
					CustomRespCode = resp.RespStatusCode
					CustomRespTitle = resp.RespTitle
					CustomTarget = resp.Url
					CustomFaviconMd5 = resp.faviconMd5
					CustomFaviconHash = resp.faviconHash
				}

				url = CustomTarget
				FaviconMd5 = CustomFaviconMd5
				FaviconHash = CustomFaviconHash
				RespBody = CustomRespBody
				RespHeader = CustomRespHeader
				RespTitle = CustomRespTitle
				RespCode = CustomRespCode

				// If the http request fails, then RespBody and RespHeader are both null
				// At this time, it is considered that the url does not exist
				if RespBody == RespHeader {
					return
				}
				if rule.Mode == "" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "CustomRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "or" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "and" {
					index := 0
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							index = index + 1
						}
					}
					if index == 2 {
						IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
						RequestRule = "CustomRequest"
					}
				}
				if rule.Mode == "and|and" {
					index := 0
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							index = index + 1
						}
					}
					if index == 4 {
						IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
						RequestRule = "CustomRequest"
					}
				}
				if rule.Mode == "or|or" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "and|or" {
					grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
					allType := grep.FindStringSubmatch(rule.Type)
					if len(regexp.MustCompile("header").FindAllStringIndex(allType[1], -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(allType[1], -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(allType[1], -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(allType[1], -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "or|and" {
					grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
					allType := grep.FindStringSubmatch(rule.Type)
					if len(regexp.MustCompile("header").FindAllStringIndex(allType[3], -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(allType[3], -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(allType[3], -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(allType[3], -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							successType = rule.Type
							return
						}
					}
				}

			} else { //默认请求
				url = DefaultTarget
				FaviconMd5 = DefaultFaviconMd5
				FaviconHash = DefaultFaviconHash
				RespBody = DefaultRespBody
				RespHeader = DefaultRespHeader
				RespCode = DefaultRespCode
				RespTitle = DefaultRespTitle

				// If the http request fails, then RespBody and RespHeader are both null
				// At this time, it is considered that the url does not exist, 认为url不存在

				if RespBody == RespHeader {
					return
				}
				if rule.Mode == "" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "or" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "and" {
					index := 0
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							index = index + 1
						}
					}
					if index == 2 {
						IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
						RequestRule = "DefaultRequest"
					}
				}
				if rule.Mode == "and|and" {
					index := 0
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							index = index + 1
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							index = index + 1
						}
					}
					if index == 4 {
						IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
						RequestRule = "DefaultRequest"
					}
				}
				if rule.Mode == "or|or" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == true {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "and|or" {
					grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
					allType := grep.FindStringSubmatch(rule.Type)
					if len(regexp.MustCompile("header").FindAllStringIndex(allType[1], -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(allType[1], -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(allType[1], -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(allType[1], -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "or|and" {
					grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
					allType := grep.FindStringSubmatch(rule.Type)
					if len(regexp.MustCompile("header").FindAllStringIndex(allType[3], -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(allType[3], -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoMd5").FindAllStringIndex(allType[3], -1)) == 1 {
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkFaviconMd5(FaviconMd5, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("icoHash").FindAllStringIndex(allType[3], -1)) == 1 {
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkFaviconHash(FaviconHash, rule.Rule.InIcoHash) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{Name: rule.Name, Rank: rule.Rank, Type: rule.Type})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
				}
			}
		}(rule)

	}
	wg.Wait()

	switch RequestRule {
	case "DefaultRequest":
		RespBody = DefaultRespBody
		RespHeader = DefaultRespHeader
		RespCode = DefaultRespCode
		RespTitle = DefaultRespTitle
		url = DefaultTarget
	case "CustomRequest":
		url = CustomTarget
		RespBody = CustomRespBody
		RespHeader = CustomRespHeader
		RespCode = CustomRespCode
		RespTitle = CustomRespTitle
	}

	for _, rs := range IdentifyData {
		//switch rs.Rank {
		//case 1:
		//	identifyResult += rs.Name + " "
		//case 2:
		//	identifyResult += rs.Name + " "
		//case 3:
		//	identifyResult += rs.Name + " "
		//}
		identifyResultArr = append(identifyResultArr, strings.ToLower(rs.Name))
	}
	//获取Technologies，将Technologies放到identify_result
	if len(R) > 0 {
		technologies, err := getTechnologies(R[0].Response.Header, R[0].RespBody)
		if err == nil {
			for _, technology := range technologies {
				identifyResultArr = append(identifyResultArr, technology)
			}
		}
	}

	if len(identifyResultArr) > 0 {
		identifyResultArr = ArrayUnique(identifyResultArr)
		identifyResult = strings.Join(identifyResultArr, ",")
	}

	res := []IdentifyResult{{successType, RespCode, identifyResult, url, RespTitle}}
	return res, err
}

type RespLab struct {
	Url            string
	RespBody       string
	RespHeader     string
	RespStatusCode string
	RespTitle      string
	faviconMd5     string
	faviconHash    int64
	Response       *http.Response
}

type IdentifyResult struct {
	Type     string
	RespCode string
	Result   string
	Url      string
	Title    string
}

func defaultRequests(Url string, timeout int) ([]RespLab, error) {
	var redirectUrl string
	var responseTitle string
	var responseHeader string
	var responseBody string
	var responseStatusCode string
	var res []string

	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return nil, err
	}

	// 设置request header
	for key, value := range DefaultHeader {
		req.Header.Set(key, value)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko,hzon-bas) Chrome/137.0.0.0 Safari/537.36")
	//跳过证书验证
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	cookieJar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: tr,
		Jar:       cookieJar,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	//获取response status code
	var statusCode = response.StatusCode
	responseStatusCode = strconv.Itoa(statusCode) //int转换为string

	// -------------------------------------------------------------------------------
	// When the http request is 302 or other 30x, 跳转问题
	// Need to intercept the request and get the return status code for display,
	// Send the request again according to the redirect url
	// In the custom request, the return status code is not checked
	// -------------------------------------------------------------------------------

	if len(regexp.MustCompile("30").FindAllStringIndex(responseStatusCode, -1)) == 1 {
		redirectPath := response.Header.Get("Location")
		if len(regexp.MustCompile("http").FindAllStringIndex(redirectPath, -1)) == 1 {
			redirectUrl = redirectPath
		} else {
			if Url[len(Url)-1:] == "/" {
				redirectUrl = Url + redirectPath
			}
			redirectUrl = Url + "/" + redirectPath
		}
		req, err := http.NewRequest("GET", redirectUrl, nil)
		if err != nil {
			return nil, err
		}
		// 设置header
		for key, value := range DefaultHeader {
			req.Header.Set(key, value)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko,hzon-bas) Chrome/137.0.0.0 Safari/537.36")
		client := &http.Client{
			Transport: tr,
			Jar:       cookieJar,
			Timeout:   time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		response, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()

		//解决30x跳转问题
		var twoStatusCode = response.StatusCode
		responseStatusCodeTwo := strconv.Itoa(twoStatusCode)
		if len(regexp.MustCompile("30").FindAllStringIndex(responseStatusCodeTwo, -1)) == 1 {
			redirectPath := response.Header.Get("Location")
			if len(regexp.MustCompile("http").FindAllStringIndex(redirectPath, -1)) == 1 {
				redirectUrl = redirectPath
			} else {
				redirectUrl = Url + redirectPath
			}
			req, err := http.NewRequest("GET", redirectUrl, nil)
			if err != nil {
				return nil, err
			}

			// 设置header
			for key, value := range DefaultHeader {
				req.Header.Set(key, value)
			}
			client := &http.Client{
				Transport: tr,
				Jar:       cookieJar,
				Timeout:   time.Duration(timeout) * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			response, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()

			// 获取 response body，并转换为string
			bodyBytes, err := ioutil.ReadAll(response.Body)
			responseBody = string(bodyBytes)
			// 解决body中乱码问题
			if !utf8.Valid(bodyBytes) {
				data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(bodyBytes)
				responseBody = string(data)
			}

			// 获取response title
			grepTitle := regexp.MustCompile("<title>(.*)</title>")
			if len(grepTitle.FindStringSubmatch(responseBody)) != 0 {
				responseTitle = grepTitle.FindStringSubmatch(responseBody)[1]
			} else {
				responseTitle = ""
			}

			// 获取response header for string
			for name, values := range response.Header {
				for _, value := range values {
					res = append(res, fmt.Sprintf("%s: %s", name, value))
				}
			}
			for _, re := range res {
				responseHeader += re + "\n"
			}

			//md5 hash
			faviconMd5 := getFaviconMd5(Url, timeout)
			faviconHash, _ := getFaviconHash(Url, timeout)
			//返回值
			RespData := []RespLab{
				{
					redirectUrl,
					responseBody,
					responseHeader,
					responseStatusCode,
					responseTitle,
					faviconMd5,
					faviconHash,
					response,
				},
			}
			return RespData, nil
		}

		// 获取 response body for string
		bodyBytes, err := ioutil.ReadAll(response.Body)
		responseBody = string(bodyBytes)
		// Solve the problem of garbled body codes with unmatched numbers
		if !utf8.Valid(bodyBytes) {
			data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(bodyBytes)
			responseBody = string(data)
		}

		//获取 response title
		grepTitle := regexp.MustCompile("<title>(.*)</title>")
		if len(grepTitle.FindStringSubmatch(responseBody)) != 0 {
			responseTitle = grepTitle.FindStringSubmatch(responseBody)[1]
		} else {
			responseTitle = "None"
		}

		// 获取response header for string
		for name, values := range response.Header {
			for _, value := range values {
				res = append(res, fmt.Sprintf("%s: %s", name, value))
			}
		}
		for _, re := range res {
			responseHeader += re + "\n"
		}

		//md5 hash
		faviconMd5 := getFaviconMd5(Url, timeout)
		faviconHash, _ := getFaviconHash(Url, timeout)
		//返回数据
		RespData := []RespLab{
			{
				redirectUrl,
				responseBody,
				responseHeader,
				responseStatusCode,
				responseTitle,
				faviconMd5,
				faviconHash,
				response,
			},
		}
		return RespData, nil
	}

	//获取response body for string
	bodyBytes, err := ioutil.ReadAll(response.Body)
	responseBody = string(bodyBytes)
	// 解决乱码问题
	if !utf8.Valid(bodyBytes) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(bodyBytes)
		responseBody = string(data)
	}

	//获取response title
	grepTitle := regexp.MustCompile("<title>(.*)</title>")
	if len(grepTitle.FindStringSubmatch(responseBody)) != 0 {
		responseTitle = grepTitle.FindStringSubmatch(responseBody)[1]
	} else {
		responseTitle = "None"
	}

	//获取response header for string
	for name, values := range response.Header {
		for _, value := range values {
			res = append(res, fmt.Sprintf("%s: %s", name, value))
		}
	}
	for _, re := range res {
		responseHeader += re + "\n"
	}

	// md5 hash
	faviconMd5 := getFaviconMd5(Url, timeout)
	faviconHash, _ := getFaviconHash(Url, timeout)
	//返回数据
	RespData := []RespLab{
		{
			Url,
			responseBody,
			responseHeader,
			responseStatusCode,
			responseTitle,
			faviconMd5,
			faviconHash,
			response,
		},
	}
	return RespData, nil

}

func customRequests(Url string, timeout int, Method string, Path string, Header []string, Body string) ([]RespLab, error) {
	var respTitle string
	//拼接自定义路径
	u, err := url.Parse(Url)
	u.Path = path.Join(u.Path, Path)
	Url = u.String()
	if strings.HasSuffix(Path, "/") {
		Url = Url + "/"
	}

	//发送http requests
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	bodyByte := bytes.NewBuffer([]byte(Body))
	req, err := http.NewRequest(Method, Url, bodyByte)
	if err != nil {
		return nil, err
	}

	//设置Requests Headers
	for _, header := range Header {
		grepKey := regexp.MustCompile("(.*): ")
		var headerKey = grepKey.FindStringSubmatch(header)[1]
		grepValue := regexp.MustCompile(": (.*)")
		var headerValue = grepValue.FindStringSubmatch(header)[1]
		req.Header.Set(headerKey, headerValue)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko,hzon-bas) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	//获取response body for string
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	var responseBody = string(bodyBytes)

	//解决body中的乱码问题
	if !utf8.Valid(bodyBytes) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(bodyBytes)
		responseBody = string(data)
	}

	//获取response title
	grepTitle := regexp.MustCompile("<title>(.*)</title>")
	if len(grepTitle.FindStringSubmatch(responseBody)) != 0 {
		respTitle = grepTitle.FindStringSubmatch(responseBody)[1]
	} else {
		respTitle = "None"
	}

	//获取response header for string
	var res []string
	for name, values := range resp.Header {
		for _, value := range values {
			res = append(res, fmt.Sprintf("%s: %s", name, value))
		}
	}
	var responseHeader string
	for _, re := range res {
		responseHeader += re + "\n"
	}

	//获取response status code
	var statusCode = resp.StatusCode
	responseStatusCode := strconv.Itoa(statusCode)
	//返回数据
	RespData := []RespLab{
		{
			Url,
			responseBody,
			responseHeader,
			responseStatusCode,
			respTitle,
			"",
			0,
			resp,
		},
	}
	return RespData, nil

}

func getTechnologies(respHeader map[string][]string, respBody string) (tech []string, err error) {
	wapp, _ := wappalyzer.New()
	matches := wapp.Fingerprint(respHeader, []byte(respBody))
	for match, _ := range matches {
		tech = append(tech, match)
	}
	return tech, nil
}

func getFaviconMd5(Url string, timeout int) string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	Url = Url + "/favicon.ico"
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return ""
	}
	for key, value := range DefaultHeader {
		req.Header.Set(key, value)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko,hzon-bas) Chrome/137.0.0.0 Safari/537.36")
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	hash := md5.Sum(bodyBytes)
	md5Hash := fmt.Sprintf("%x", hash)
	return md5Hash
}

func getFaviconHash(imageURL string, timeout int) (int64, error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	imageURL = imageURL + "/favicon.ico"
	req, err := http.NewRequest("GET", imageURL, nil)
	if err != nil {
		return 0, err
	}
	for key, value := range DefaultHeader {
		req.Header.Set(key, value)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko,hzon-bas) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	// 将图片数据转换为 Base64 编码
	base64Encoded := base64.StdEncoding.EncodeToString(bodyBytes)
	var base64Str string
	if base64Encoded != "" {
		if body, err := base64.StdEncoding.DecodeString(base64Encoded); err != nil {
			return 0, err
		} else {
			base64Str = string(body)
		}
	}
	return cast.ToInt64(Mmh3Hash32(Mmh3Base64Encode(base64Str))), nil
}

func checkHeader(url, responseHeader string, ruleHeader string, name string, title string, RespCode string) bool {
	//ruleHeader = regexp2.Escape(ruleHeader)
	ruleHeader = fmt.Sprintf(`(?i)%v`, fmt.Sprintf(`(%v)`, ruleHeader))
	reg, err := regexp2.Compile(ruleHeader, 0)
	if err != nil {
		return false
	}
	match, _ := reg.MatchString(responseHeader)
	if match {
		return true
	} else {
		return false
	}
}

func checkBody(url, responseBody string, ruleBody string, name string, title string, RespCode string) bool {
	//ruleBody = regexp2.Escape(ruleBody)
	ruleBody = fmt.Sprintf(`(?i)%v`, ruleBody)
	reg, err := regexp2.Compile(ruleBody, 0)
	if err != nil {
		return false
	}
	match, _ := reg.MatchString(responseBody)
	if match {
		return true
	} else {
		return false
	}
}

func checkFaviconMd5(Favicon, ruleFaviconMd5 string) bool {
	ruleFaviconMd5 = fmt.Sprintf(`(?i)%v`, ruleFaviconMd5)
	reg, err := regexp2.Compile(ruleFaviconMd5, 0)
	if err != nil {
		return false
	}
	match, _ := reg.MatchString(Favicon)
	if match {
		return true
	} else {
		return false
	}
}

func checkFaviconHash(FaviconHash, ruleFaviconHash int64) bool {
	if FaviconHash == ruleFaviconHash {
		return true
	} else {
		return false
	}
}
