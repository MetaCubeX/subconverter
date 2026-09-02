package parser

import (
	"fmt"
	"strings"

	"subconv/internal/model"
)

// parseVLESS 解析 vless://uuid@host:port?params#name 链接（含 REALITY 全参数）。
// 参考 C++ 版 explodeStdVLESS。参数映射：
//
//	encryption            —— vless 固定为 none，本期模型无对应字段，忽略
//	security              —— reality / tls 时置 TLSSecure=true
//	sni（缺省回退 peer） —— SNI
//	fp                    —— ClientFingerprint（uTLS 指纹）
//	pbk / sid             —— REALITY PublicKey / ShortID（sid 经 SanitizeShortID 清洗）
//	flow                  —— Flow（如 xtls-rprx-vision）
//	type                  —— 传输层 Network：tcp/ws/grpc/h2/http/quic
//	host / path           —— ws/h2 的 Host 头与路径
//	serviceName / mode    —— grpc 服务名与模式（mode 缺省 gun，对齐 C++ vlessConstruct）
//	alpn                  —— 逗号分隔，拆为 ALPN 切片
//	insecure/allowInsecure —— SkipCertVerify
func parseVLESS(link string) (*model.Proxy, error) {
	body := strings.TrimPrefix(link, "vless://")
	body, query, remark := parseLinkParts(body)

	uuid, host, port, err := splitUserHostPort(body)
	if err != nil {
		return nil, fmt.Errorf("vless 链接主机部分非法: %w", err)
	}
	if uuid == "" {
		return nil, fmt.Errorf("vless 链接缺少 UUID")
	}

	q := parseQuery(query)
	node := &model.Proxy{
		Type:              model.TypeVLESS,
		Name:              remark,
		Server:            host,
		Port:              port,
		UUID:              uuid,
		Flow:              q["flow"],
		PublicKey:         q["pbk"],
		ShortID:           q["sid"],
		ClientFingerprint: q["fp"],
		Fingerprint:       q["hpkp"],
		SNI:               firstNonEmpty(q["sni"], q["peer"]),
	}

	// security=reality 或 tls → 开启 TLS
	switch q["security"] {
	case "reality", "tls":
		node.TLSSecure = true
	}

	// insecure 缺省回退 allowInsecure（对齐 C++ explodeStdVLESS）
	node.SkipCertVerify = parseBoolParam(firstNonEmpty(q["insecure"], q["allowInsecure"]))

	// 传输层。type 缺省 tcp（比 C++ 更宽容：C++ 对缺省/未知 type 直接丢弃节点）
	network := q["type"]
	if network == "" {
		network = "tcp"
	}
	node.Network = network
	switch network {
	case "tcp", "quic":
		// 无传输层附加字段
	case "ws", "h2", "http":
		if p := q["path"]; p != "" {
			node.WSPath = urlDecode(p)
		}
		if h := q["host"]; h != "" {
			node.WSHeaders = map[string]string{"Host": urlDecode(h)}
		}
	case "grpc":
		node.GRPCServiceName = urlDecode(q["serviceName"])
		if mode := q["mode"]; mode != "" {
			node.GRPCMode = mode
		} else {
			node.GRPCMode = "gun"
		}
	default:
		return nil, fmt.Errorf("vless 链接不支持的传输类型: %q", network)
	}

	node.ALPN = splitALPN(q["alpn"])

	// 节点名称缺省 host:port
	if node.Name == "" {
		node.Name = defaultName(host, port)
	}
	return node, nil
}

func init() {
	register(parseVLESS, "vless")
}
