package definger

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
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
	var Favicon string
	var RequestRule string
	var DefaultRespTitle string
	var DefaultRespBody string
	var DefaultRespHeader string
	var DefaultRespCode string
	var DefaultTarget string
	var DefaultFavicon string
	var DefaultTechnologies []string
	var CustomRespTitle string
	var CustomRespBody string
	var CustomRespHeader string
	var CustomRespCode string
	var CustomTarget string
	var CustomFavicon string

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
		DefaultFavicon = resp.faviconMd5
		DefaultTechnologies = resp.Technologies
	}

	// 开始识别
	var successType string
	var identify_result string
	var category string

	type Identify_Result struct {
		Name     string
		Category string
		Rank     int
		Type     string
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
					CustomFavicon = resp.faviconMd5
				}

				url = CustomTarget
				Favicon = CustomFavicon
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
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "CustomRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "or" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
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
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							index = index + 1
						}
					}
					if index == 2 {
						IdentifyData = append(IdentifyData, Identify_Result{
							Name:     rule.Name,
							Category: rule.Category,
							Rank:     rule.Rank,
							Type:     rule.Type,
						})
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
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							index = index + 1
						}
					}
					if index == 3 {
						IdentifyData = append(IdentifyData, Identify_Result{
							Name:     rule.Name,
							Category: "",
							Rank:     rule.Rank,
							Type:     rule.Type,
						})
						RequestRule = "CustomRequest"
					}
				}
				if rule.Mode == "or|or" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "and|or" {
					grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
					all_type := grep.FindStringSubmatch(rule.Type)
					if len(regexp.MustCompile("header").FindAllStringIndex(all_type[1], -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(all_type[1], -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[1], -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "or|and" {
					grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
					all_type := grep.FindStringSubmatch(rule.Type)
					fmt.Println(all_type)
					if len(regexp.MustCompile("header").FindAllStringIndex(all_type[3], -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(all_type[3], -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[3], -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							successType = rule.Type
							return
						}
					}
				}

			} else { //默认请求
				url = DefaultTarget
				Favicon = DefaultFavicon
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
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "or" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
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
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							index = index + 1
						}
					}
					if index == 2 {
						IdentifyData = append(IdentifyData, Identify_Result{
							Name:     rule.Name,
							Category: rule.Category,
							Rank:     rule.Rank,
							Type:     rule.Type,
						})
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
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							index = index + 1
						}
					}
					if index == 3 {
						IdentifyData = append(IdentifyData, Identify_Result{
							Name:     rule.Name,
							Category: rule.Category,
							Rank:     rule.Rank,
							Type:     rule.Type,
						})
						RequestRule = "DefaultRequest"
					}
				}
				if rule.Mode == "or|or" {
					if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "and|or" {
					grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
					all_type := grep.FindStringSubmatch(rule.Type)
					fmt.Println(all_type)
					if len(regexp.MustCompile("header").FindAllStringIndex(all_type[1], -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(all_type[1], -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[1], -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
				}
				if rule.Mode == "or|and" {
					grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
					all_type := grep.FindStringSubmatch(rule.Type)
					fmt.Println(all_type)
					if len(regexp.MustCompile("header").FindAllStringIndex(all_type[3], -1)) == 1 {
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("body").FindAllStringIndex(all_type[3], -1)) == 1 {
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
					}
					if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[3], -1)) == 1 {
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
							RequestRule = "DefaultRequest"
							successType = rule.Type
							return
						}
						if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
							IdentifyData = append(IdentifyData, Identify_Result{
								Name:     rule.Name,
								Category: rule.Category,
								Rank:     rule.Rank,
								Type:     rule.Type,
							})
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

	if RequestRule == "DefaultRequest" {
		RespBody = DefaultRespBody
		RespHeader = DefaultRespHeader
		RespCode = DefaultRespCode
		RespTitle = DefaultRespTitle
		url = DefaultTarget
	} else if RequestRule == "CustomRequest" {
		url = CustomTarget
		RespBody = CustomRespBody
		RespHeader = CustomRespHeader
		RespCode = CustomRespCode
		RespTitle = CustomRespTitle
	}

	for _, rs := range IdentifyData {
		if rs.Category != "" {
			if res, ok := CateData[rs.Category]; ok {
				category = res.Name
			}
		}
		switch rs.Rank {
		case 1:
			identify_result += rs.Name + " "
		case 2:
			identify_result += rs.Name + " "
		case 3:
			identify_result += rs.Name + " "
		}
	}
	//r := strings.ReplaceAll(identify_result, "][", "] [")

	res := []IdentifyResult{{successType,
		RespCode,
		identify_result,
		url,
		RespTitle,
		category,
		0,
		DefaultTechnologies}}
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
	Technologies   []string
}

type IdentifyResult struct {
	Type         string
	RespCode     string
	Result       string
	Url          string
	Title        string
	Category     string
	Level        int
	Technologies []string
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
	//跳过证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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

	defer func() {
		_ = response.Body.Close()
	}()

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
		defer func() {
			_ = response.Body.Close()
		}()

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
			defer func() {
				_ = response.Body.Close()
			}()

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
			technologies, _ := getTechnologies(response.Header, bodyBytes)
			//返回值
			RespData := []RespLab{
				{redirectUrl, responseBody, responseHeader, responseStatusCode, responseTitle, faviconMd5, faviconHash, technologies},
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
		technologies, _ := getTechnologies(response.Header, bodyBytes)
		//返回数据
		RespData := []RespLab{
			{redirectUrl, responseBody, responseHeader, responseStatusCode, responseTitle, faviconMd5, faviconHash, technologies},
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
	technologies, _ := getTechnologies(response.Header, bodyBytes)
	//返回数据
	RespData := []RespLab{
		{Url, responseBody, responseHeader, responseStatusCode, responseTitle, faviconMd5, faviconHash, technologies},
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

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
	technologies, _ := getTechnologies(resp.Header, bodyBytes)
	//返回数据
	RespData := []RespLab{
		{Url, responseBody, responseHeader, responseStatusCode, respTitle, "", 0, technologies},
	}
	return RespData, nil

}

func getTechnologies(header map[string][]string, data []byte) (tech []string, err error) {
	wapp, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	matches := wapp.Fingerprint(header, data)
	for match, _ := range matches {
		tech = append(tech, match)
	}
	return tech, nil
}

func getFaviconMd5(Url string, timeout int) string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
	grep := regexp.MustCompile("(?i)" + ruleHeader) // 表示ruleHeader不区分大小写
	if len(grep.FindStringSubmatch(responseHeader)) != 0 {
		return true
	} else {
		return false
	}
}

func checkBody(url, responseBody string, ruleBody string, name string, title string, RespCode string) bool {
	grep := regexp.MustCompile("(?i)" + ruleBody)
	if len(grep.FindStringSubmatch(responseBody)) != 0 {
		return true
	} else {
		return false
	}
}

func checkFavicon(Favicon, ruleFaviconMd5 string) bool {
	grep := regexp.MustCompile("(?i)" + ruleFaviconMd5)
	if len(grep.FindStringSubmatch(Favicon)) != 0 {
		return true
	} else {
		return false
	}
}
