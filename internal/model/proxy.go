// Package model 定义订阅转换的核心数据模型。
// 字段设计对齐 REWRITE_PLAN §3.1：所有协议解析为统一 Proxy 结构，
// 渲染层（Phase 2）只消费该结构，不再感知具体 URI 语法。
package model

// ProxyType 节点协议类型。
type ProxyType int

// 支持的协议类型常量。
const (
	TypeUnknown   ProxyType = iota
	TypeVLESS               // vless（含 REALITY）
	TypeVMess               // vmess
	TypeSS                  // shadowsocks
	TypeTrojan              // trojan
	TypeHysteria2           // hysteria2 / hy2
	TypeAnyTLS              // anytls
)

// String 返回协议类型的可读名称，与 Clash/mihomo 节点 type 字段取值一致。
func (t ProxyType) String() string {
	switch t {
	case TypeVLESS:
		return "vless"
	case TypeVMess:
		return "vmess"
	case TypeSS:
		return "ss"
	case TypeTrojan:
		return "trojan"
	case TypeHysteria2:
		return "hysteria2"
	case TypeAnyTLS:
		return "anytls"
	default:
		return "unknown"
	}
}

// Proxy 单个代理节点的统一数据模型。
// 布尔类字段中仅 UDP 使用三态指针（nil = 未设置，对应 C++ 版 tribool），
// 其余布尔在本期输入侧无需区分"未设置/显式 false"，用普通 bool 即可。
type Proxy struct {
	Type   ProxyType
	Name   string
	Server string
	Port   int
	UDP    *bool // 三态：nil 表示未设置，渲染时仅输出显式设置过的值
	Group  string

	// VLESS / REALITY
	UUID              string
	Flow              string
	PublicKey         string // REALITY public-key（pbk）
	ShortID           string // REALITY short-id（sid），原样透传不做校验
	ClientFingerprint string // uTLS 指纹（fp，如 chrome）
	SNI               string
	Fingerprint       string // 证书指纹（hpkp）

	// VMess
	AlterID  int
	Security string // 加密方式：auto / aes-128-gcm / chacha20-poly1305 ...

	// SS / Trojan / AnyTLS
	Cipher   string
	Password string

	// 传输层
	Network         string // tcp / ws / grpc / http / h2
	WSPath          string
	WSHeaders       map[string]string // WebSocket 头，通常只有 Host
	GRPCServiceName string
	GRPCMode        string // gun / multi

	// TLS
	TLSSecure      bool
	SkipCertVerify bool
	ALPN           []string

	// Hysteria2
	Hysteria2Obfs         string // 混淆协议，通常为 salamander
	Hysteria2ObfsPassword string
	Hysteria2Ports        string // 端口跳跃范围，如 "2080:3000"
}

// BoolPtr 返回 bool 的指针，用于三态字段赋值。
func BoolPtr(b bool) *bool { return &b }
