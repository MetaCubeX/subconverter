package parser

import (
	"fmt"
	"strings"

	"subconv/internal/model"
)

// parseAnyTLS 解析 anytls://password@host:port?params#name 链接，
// 参考 C++ 版 explodeStdAnyTLS。参数映射：
//
//	sni（缺省回退 peer，对齐 C++）—— SNI
//	insecure                  —— SkipCertVerify
//	alpn                      —— ALPN
//
// anytls 天然基于 TLS，TLSSecure 恒为 true。
func parseAnyTLS(link string) (*model.Proxy, error) {
	body, query, remark := parseLinkParts(strings.TrimPrefix(link, "anytls://"))

	password, host, port, err := splitUserHostPort(body)
	if err != nil {
		return nil, fmt.Errorf("anytls 链接主机部分非法: %w", err)
	}
	if password == "" {
		return nil, fmt.Errorf("anytls 链接缺少密码")
	}

	q := parseQuery(query)
	node := &model.Proxy{
		Type:           model.TypeAnyTLS,
		Name:           remark,
		Server:         host,
		Port:           port,
		Password:       password,
		SNI:            firstNonEmpty(q["sni"], q["peer"]),
		TLSSecure:      true,
		SkipCertVerify: parseBoolParam(q["insecure"]),
		ALPN:           splitALPN(q["alpn"]),
	}

	if node.Name == "" {
		node.Name = defaultName(host, port)
	}
	return node, nil
}

func init() {
	register(parseAnyTLS, "anytls")
}
