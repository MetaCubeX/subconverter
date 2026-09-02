package parser

import (
	"fmt"
	"strings"

	"subconv/internal/model"
)

// parseHysteria2 解析 hysteria2://password@host:port?params#name 链接
// （hy2:// 为别名），参考 C++ 版 explodeStdHysteria2。参数映射：
//
//	obfs / obfs-password —— Hysteria2Obfs / Hysteria2ObfsPassword（salamander 混淆）
//	sni                  —— SNI
//	insecure             —— SkipCertVerify
//	mport / ports        —— Hysteria2Ports 端口跳跃范围
//	alpn                 —— ALPN
//
// hysteria2 天然基于 TLS（QUIC），TLSSecure 恒为 true。
func parseHysteria2(link string) (*model.Proxy, error) {
	body := link
	if strings.HasPrefix(link, "hysteria2://") {
		body = strings.TrimPrefix(link, "hysteria2://")
	} else {
		body = strings.TrimPrefix(link, "hy2://")
	}
	body, query, remark := parseLinkParts(body)

	password, host, port, err := splitUserHostPort(body)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 链接主机部分非法: %w", err)
	}
	if password == "" {
		return nil, fmt.Errorf("hysteria2 链接缺少密码")
	}

	q := parseQuery(query)
	node := &model.Proxy{
		Type:                  model.TypeHysteria2,
		Name:                  remark,
		Server:                host,
		Port:                  port,
		Password:              password,
		Hysteria2Obfs:         q["obfs"],
		Hysteria2ObfsPassword: q["obfs-password"],
		Hysteria2Ports:        firstNonEmpty(q["mport"], q["ports"]),
		SNI:                   q["sni"],
		TLSSecure:             true,
		SkipCertVerify:        parseBoolParam(q["insecure"]),
		ALPN:                  splitALPN(q["alpn"]),
	}

	if node.Name == "" {
		node.Name = defaultName(host, port)
	}
	return node, nil
}

func init() {
	register(parseHysteria2, "hysteria2", "hy2")
}
