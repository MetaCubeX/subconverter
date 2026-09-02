package parser

import (
	"fmt"
	"strings"

	"subconv/internal/model"
)

// parseSS 解析 shadowsocks 链接，参考 C++ 版 explodeSS。支持两种形态：
//
//	ss://base64(method:password)@host:port?plugin=...#name   （SIP002，含 plugin 变体）
//	ss://base64(method:password@host:port)#name              （旧式整体 base64）
//
// SIP002 的 userinfo 优先按 base64 解码；解码失败或不含冒号时回退按明文
// "method:password" 处理（比 C++ 的宽松解码更稳：C++ 会把明文编成乱码）。
// plugin 参数（obfs-local 等）本期模型无对应字段，解析时接受但忽略。
func parseSS(link string) (*model.Proxy, error) {
	// 兼容个别生成端在 ? 前多写的斜杠："/?" → "?"（对齐 C++ explodeSS）
	body := strings.ReplaceAll(strings.TrimPrefix(link, "ss://"), "/?", "?")
	body, query, remark := parseLinkParts(body)

	// plugin/group 等查询参数：本期仅接受不落地（解析失败才算错误）
	_ = parseQuery(query)

	var method, password, host string
	var port int

	if at := strings.Index(body, "@"); at >= 0 {
		// SIP002：userinfo@host:port
		var err error
		host, port, err = splitHostPort(body[at+1:])
		if err != nil {
			return nil, fmt.Errorf("ss 链接主机部分非法: %w", err)
		}
		method, password = decodeMethodPassword(body[:at])
	} else {
		// 旧式：整体 base64(method:password@host:port)
		data, err := base64DecodeAny(body)
		if err != nil {
			return nil, fmt.Errorf("ss 链接 base64 解码失败: %w", err)
		}
		s := string(data)
		colon := strings.Index(s, ":")
		at := strings.LastIndex(s, "@")
		if colon <= 0 || at < colon {
			return nil, fmt.Errorf("ss 链接内容缺少 method:password@host:port 结构")
		}
		method = s[:colon]
		password = s[colon+1 : at]
		host, port, err = splitHostPort(s[at+1:])
		if err != nil {
			return nil, fmt.Errorf("ss 链接主机部分非法: %w", err)
		}
	}

	if method == "" {
		return nil, fmt.Errorf("ss 链接缺少加密方式")
	}

	name := remark
	if name == "" {
		name = defaultName(host, port)
	}
	return &model.Proxy{
		Type:     model.TypeSS,
		Name:     name,
		Server:   host,
		Port:     port,
		Cipher:   method,
		Password: password,
	}, nil
}

// decodeMethodPassword 解码 SIP002 的 userinfo：
// 先按 base64 解 "method:password"，失败或不含冒号则回退明文。
func decodeMethodPassword(userinfo string) (method, password string) {
	if data, err := base64DecodeAny(userinfo); err == nil {
		if m, p, ok := splitOnFirstColon(string(data)); ok {
			return m, p
		}
	}
	// 明文回退（部分生成端不做 base64）
	if m, p, ok := splitOnFirstColon(userinfo); ok {
		return m, p
	}
	return "", ""
}

// splitOnFirstColon 按第一个冒号拆分（密码可含冒号），无冒号返回 false。
func splitOnFirstColon(s string) (left, right string, ok bool) {
	if idx := strings.Index(s, ":"); idx > 0 {
		return s[:idx], s[idx+1:], true
	}
	return "", "", false
}

func init() {
	register(parseSS, "ss")
}
