package pac

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// 黑白名单列表
var whiteRules, blackRules []string

//  补充黑名单常见数据
var supBlackRules = []string{
	"google.",
	"youtube.",
	"facebook.",
	"twitter.",
}

// 初始化规则
func InitRule() {
	// 初始化黑名单
	blackRules = getBlackRule()
	// 补充黑名单规则
	blackRules = append(blackRules, supBlackRules...)
}

// 新增规则 竖线为分隔符
func AddRules(mode, userRules string) {
	newRules := strings.Split(userRules, "|")
	if len(newRules) <= 0 {
		return
	}
	if mode == "white" {
		whiteRules = append(whiteRules, newRules...)
	} else {
		blackRules = append(blackRules, newRules...)
	}
}

// 是否需要代理
func IsNeedProxy(domain string) bool {
	domain = strings.ToLower(domain)
	// 是否在白名单内
	for _, v := range whiteRules {
		v = strings.ToLower(v)
		if strings.Contains(domain, v) && len(v) > 0 {
			return false
		}
	}
	// 是否在黑名单内
	for _, v := range blackRules {
		v = strings.ToLower(v)
		if strings.Contains(domain, v) && len(v) > 0 {
			return true
		}
	}
	return false
}

// 获得黑名单列表
func getBlackRule() []string {
	pacFile, _ := filepath.Abs(os.TempDir() + "/bargo_pac.txt")
	// 缓存是否过期
	fileinfo, err := os.Stat(pacFile)
	if err != nil || fileinfo.ModTime().Add(24 * 7 * time.Hour).Before(time.Now()) {
		err := updatePacFile(pacFile)
		if err != nil {
			panic(err)
		}
	}
	data, err := ioutil.ReadFile(pacFile)
	if err != nil {
		panic(err)
	}
	rules := strings.Split(string(data), "\n")

	return rules
}

// 更新缓存文件
func updatePacFile(pacFile string) error {
	// 默认走缓存的gfw数据
	gfwBase64String := DEFAULT_GFWLIST
	// 远程获取新数据
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(GFWLIST_URL)
	if err == nil && resp.StatusCode == 200 {
		gfwBase64, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err == nil && len(gfwBase64) > 200 {
			gfwBase64String = string(gfwBase64)
		}
	}

	// 打开缓存文件
	cachefile, err := os.OpenFile(pacFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer cachefile.Close()
	// 解析gfwlist
	gfwRule, err := base64.StdEncoding.DecodeString(gfwBase64String)
	if err != nil {
		return err
	}
	gfwRuleReader := bufio.NewReader(bytes.NewReader(gfwRule))
	// 保存结果用于去重
	result := make(map[string]int)
	for {
		// 开始匹配每一行
		line, _, err := gfwRuleReader.ReadLine()
		if err != nil {
			break
		}
		lineStr := string(line)
		if len(line) == 0 {
			continue
		}
		reg := regexp.MustCompile(`[!\[].*?`)
		isComment := reg.Match(line)
		if isComment {
			continue
		}
		isWhite := strings.HasPrefix(lineStr, "@@")
		// 匹配域名和ip
		reg = regexp.MustCompile(`(?:(?:[a-zA-Z0-9\-]{1,61}\.)+[a-zA-Z]{2,6}|(?:\d{1,3}\.){3}\d{1,3})`)
		domain := reg.FindAllStringSubmatch(lineStr, 1)
		if !isWhite && len(domain) > 0 {
			if _, ok := result[domain[0][0]]; ok {
				continue
			}
			cachefile.WriteString(domain[0][0] + "\n")
			result[domain[0][0]] = 1
		}
	}

	return nil
}
