// Package parser 实现订阅输入侧解析：单条节点 URI（各协议一个文件）
// 与订阅内容（base64 / 明文行 / Clash YAML）。
//
// registry 模式：每个协议解析器在自己的文件里通过 init() 调用 register
// 注册，ParseLink 按协议前缀分发，新增协议零侵入。
package parser

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"subconv/internal/model"
)

// linkParser 单协议链接解析函数：入参为完整 URI，出参为填充好的节点。
type linkParser func(link string) (*model.Proxy, error)

// registry 协议 scheme（小写，不含 "://"）→ 解析器。
var registry = map[string]linkParser{}

// register 注册协议解析器，scheme 为小写协议前缀，可一次注册多个别名
// （如 hysteria2 与 hy2）。
func register(f linkParser, schemes ...string) {
	for _, s := range schemes {
		registry[s] = f
	}
}

// ParseLink 解析单条节点链接，按协议前缀分发到具体解析器。
// 无法识别的协议、格式非法均返回 error；调用方（订阅逐行解析）跳过即可，
// 行为对应 C++ 版 explode() 中 Type == Unknown 的节点被丢弃。
func ParseLink(link string) (*model.Proxy, error) {
	link = strings.TrimSpace(link)
	pos := strings.Index(link, "://")
	if pos <= 0 {
		return nil, fmt.Errorf("无法识别的链接（缺少协议前缀）: %.60q", link)
	}
	p, ok := registry[strings.ToLower(link[:pos])]
	if !ok {
		return nil, fmt.Errorf("不支持的协议: %q", link[:pos])
	}
	return p(link)
}

// parseLinkParts 拆解去 scheme 后的 URI 主体：先按最后一个 # 拆出备注
// （fragment，URL 解码），再按最后一个 ? 拆出查询串。
// 与 C++ explodeStd* 系列的 rfind("#") / rfind("?") 顺序一致。
func parseLinkParts(body string) (rest, query, remark string) {
	if pos := strings.LastIndex(body, "#"); pos >= 0 {
		remark = urlDecode(body[pos+1:])
		body = body[:pos]
	}
	if pos := strings.LastIndex(body, "?"); pos >= 0 {
		query = body[pos+1:]
		body = body[:pos]
	}
	return body, query, remark
}

// splitHostPort 从 "host:port" 拆出主机与端口。端口取最后一个冒号之后的
// 纯数字串，因此天然兼容 IPv6 字面量（如 [2001:db8::1]:443），
// 与 C++ 正则 (.*):(\d+)$ 的贪婪回溯行为一致。
func splitHostPort(s string) (host string, port int, err error) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("缺少端口: %q", s)
	}
	port, err = strconv.Atoi(s[idx+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("非法端口: %q", s[idx+1:])
	}
	host = s[:idx]
	// 去掉 IPv6 方括号（成对出现时才去）
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return "", 0, fmt.Errorf("缺少主机: %q", s)
	}
	return host, port, nil
}

// splitUserHostPort 从 "user@host:port" 拆出用户信息与主机端口。
// @ 取第一个（与 C++ 非贪婪正则 (.*?)@ 一致），
// 密码/UUID 中若含 @ 需编码为 %40 后再由调用方解码。
func splitUserHostPort(s string) (user, host string, port int, err error) {
	at := strings.Index(s, "@")
	if at < 0 {
		return "", "", 0, fmt.Errorf("缺少用户信息（@）: %q", s)
	}
	host, port, err = splitHostPort(s[at+1:])
	if err != nil {
		return "", "", 0, err
	}
	return s[:at], host, port, nil
}

// parseQuery 宽松解析查询串为键值表：值做 URL 解码（'+' 转空格），
// 重复键保留首个（对应 C++ getUrlArg 语义）。
func parseQuery(q string) map[string]string {
	m := make(map[string]string)
	if q == "" {
		return m
	}
	for _, kv := range strings.Split(q, "&") {
		if kv == "" {
			continue
		}
		key, val, _ := strings.Cut(kv, "=")
		if _, exists := m[key]; !exists {
			m[key] = urlDecode(val)
		}
	}
	return m
}

// urlDecode 宽松 URL 解码：'+' 转空格、%XX 还原；存在非法转义时
// 整体原样返回（宁可保守也不报错，对应 C++ urlDecode 的容错取向）。
func urlDecode(s string) string {
	if !strings.Contains(s, "%") && !strings.Contains(s, "+") {
		return s
	}
	if dec, err := url.QueryUnescape(s); err == nil {
		return dec
	}
	return s
}

// base64DecodeAny 尝试按 base64 解码：兼容标准与 URL-safe 字母表、
// 缺省 padding，忽略混入的空白字符（\n \r 空格 \t）。失败返回 error。
func base64DecodeAny(s string) ([]byte, error) {
	// 逐字节过滤空白，避免对非 UTF-8 内容做 rune 级改写
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n', '\r', ' ', '\t':
		default:
			b.WriteByte(s[i])
		}
	}
	s = b.String()
	if s == "" {
		return nil, fmt.Errorf("base64 内容为空")
	}
	// URL-safe 字母表归一化为标准字母表，再去掉已有 padding 统一补齐
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	s = strings.TrimRight(s, "=")
	switch len(s) % 4 {
	case 0:
		return base64.StdEncoding.DecodeString(s)
	case 2:
		return base64.StdEncoding.DecodeString(s + "==")
	case 3:
		return base64.StdEncoding.DecodeString(s + "=")
	default: // 余 1 为非法长度
		return nil, fmt.Errorf("base64 长度非法")
	}
}

// parseBoolParam 解析 URI 布尔参数，对齐 C++ tribool(string) 语义：
// "true"/"1" 及大于 1 的整数为真，"false"/"0" 为假，其余（含空串）为假。
func parseBoolParam(v string) bool {
	switch v {
	case "true", "1":
		return true
	case "false", "0", "":
		return false
	}
	if n, err := strconv.Atoi(v); err == nil && n > 1 {
		return true
	}
	return false
}

// splitALPN 把逗号分隔的 alpn 参数拆为切片（"h2,http/1.1" → [h2 http/1.1]）。
func splitALPN(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// defaultName 节点缺省名称：host:port。
func defaultName(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
