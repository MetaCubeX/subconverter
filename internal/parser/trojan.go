package parser

import (
	"fmt"
	"strings"

	"subconv/internal/model"
)

// parseTrojan 解析 trojan://password@host:port?params#name 链接，
// 参考 C++ 版 explodeTrojan。参数映射：
//
//	sni（缺省回退 peer）—— SNI
//	allowInsecure（缺省回退 insecure）—— SkipCertVerify
//	alpn        —— ALPN
//	type=ws     —— Network=ws，path 为 WS 路径（X-ui 风格）
//	ws=1        —— Network=ws，wspath 为 WS 路径（v2rayN 风格）
//
// trojan 天然基于 TLS，TLSSecure 恒为 true（对齐 C++ trojanConstruct）。
func parseTrojan(link string) (*model.Proxy, error) {
	body, query, remark := parseLinkParts(strings.TrimPrefix(link, "trojan://"))

	password, host, port, err := splitUserHostPort(body)
	if err != nil {
		return nil, fmt.Errorf("trojan 链接主机部分非法: %w", err)
	}
	if password == "" {
		return nil, fmt.Errorf("trojan 链接缺少密码")
	}

	q := parseQuery(query)
	node := &model.Proxy{
		Type:           model.TypeTrojan,
		Name:           remark,
		Server:         host,
		Port:           port,
		Password:       password,
		SNI:            firstNonEmpty(q["sni"], q["peer"]),
		TLSSecure:      true,
		SkipCertVerify: parseBoolParam(firstNonEmpty(q["allowInsecure"], q["insecure"])),
		ALPN:           splitALPN(q["alpn"]),
	}

	// WebSocket 传输的两种链接风格
	switch {
	case q["type"] == "ws":
		node.Network = "ws"
		node.WSPath = urlDecode(q["path"])
		if h := q["host"]; h != "" {
			node.WSHeaders = map[string]string{"Host": urlDecode(h)}
		}
	case parseBoolParam(q["ws"]):
		node.Network = "ws"
		node.WSPath = urlDecode(q["wspath"])
	}
	if node.Network == "" {
		node.Network = "tcp"
	}

	if node.Name == "" {
		node.Name = defaultName(host, port)
	}
	return node, nil
}

func init() {
	register(parseTrojan, "trojan")
}
