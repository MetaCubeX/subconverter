// Package render 实现输出侧渲染。本期（Phase 2）完成 Clash（mihomo）YAML：
// 节点段各协议一 map、REALITY 字段强制双引号、策略组与规则由 ACL 配置驱动。
//
// 渲染统一基于 yaml.Node 手工建树（而非 struct marshal），原因：
//   - 需要精确控制字段顺序（对齐 C++ 输出习惯）与"未设置不输出"
//   - 需要对特定标量强制 DoubleQuotedStyle（REALITY short-id、纯数字密码），
//     从根本上规避裸值被下游 YAML 解析器误判为数值/布尔的类型歧义
package render

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"subconv/internal/model"
	"subconv/internal/rule"
)

// Config 渲染配置：携带 ACL 策略组/规则集定义。
// ACL 为 nil 时仅渲染节点段与 MATCH 兜底规则。
type Config struct {
	ACL *rule.ACLConfig
}

// Convert 内部调用方的统一渲染入口。
// target 支持 "clash" 与 "loon"。
func Convert(target string, nodes []model.Proxy, cfg *Config) (string, error) {
	switch target {
	case "clash":
		return RenderClash(nodes, cfg)
	case "loon":
		return RenderLoon(nodes, cfg)
	default:
		return "", fmt.Errorf("不支持的输出格式: %q（当前仅支持 clash/loon）", target)
	}
}

// clashBaseTemplate 顶部基础配置模板（硬编码，对齐 C++ base/base/simple_base.yml
// 的最小集：port/socks-port/mode/log-level 等，减少对 base/ 目录的运行期依赖）。
const clashBaseTemplate = `port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
`

// RenderClash 渲染完整 Clash（mihomo）配置：
// 基础模板 + proxies + proxy-groups（ACL 策略组）+ rules（ACL 规则集，尾部必有 MATCH）。
func RenderClash(nodes []model.Proxy, cfg *Config) (string, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	// 节点名清洗：'=' 替换为 '-'（部分客户端解析异常）+ 重名去重（C++ processRemark）
	sanitizeNodeNames(nodes)

	var buf bytes.Buffer
	buf.WriteString(clashBaseTemplate)
	buf.WriteString("proxies:\n")

	proxies := &yaml.Node{Kind: yaml.SequenceNode}
	for i := range nodes {
		node, err := renderProxy(&nodes[i])
		if err != nil {
			return "", fmt.Errorf("渲染节点 %q 失败: %w", nodes[i].Name, err)
		}
		proxies.Content = append(proxies.Content, node)
	}
	if err := writeYAMLSection(&buf, proxies); err != nil {
		return "", err
	}

	// 策略组
	groups, err := renderGroups(nodes, cfg.ACL)
	if err != nil {
		return "", err
	}
	if len(groups) > 0 {
		buf.WriteString("proxy-groups:\n")
		grpSeq := &yaml.Node{Kind: yaml.SequenceNode}
		for i := range groups {
			grpSeq.Content = append(grpSeq.Content, &groups[i])
		}
		if err := writeYAMLSection(&buf, grpSeq); err != nil {
			return "", err
		}
	}

	// 规则：加载/下载规则集 → 展开 → 保证尾部 MATCH
	rules, err := renderRules(cfg.ACL)
	if err != nil {
		return "", err
	}
	buf.WriteString("rules:\n")
	ruleSeq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, r := range rules {
		ruleSeq.Content = append(ruleSeq.Content, strNode(r))
	}
	if err := writeYAMLSection(&buf, ruleSeq); err != nil {
		return "", err
	}

	// go-yaml emitter 会把非 BMP 字符（emoji，如 🚀）转义为 \U0001F680 形式——
	// 语义等价但可读性差、与 C++ 版输出 diff 大，统一还原为字面字符
	return unescapeUnicodeEscapes(buf.String()), nil
}

// unescapeUnicodeEscapes 把 YAML 双引号字符串中的 \U0001F680 形式转义还原为字面字符。
// 扫描时成对的 \\ 视为被转义的字面反斜杠原样保留，避免误伤密码等字段中
// 恰好出现字面 "\Uxxxxxxxx" 文本的极端情况；仅还原 astral plane（>0xFFFF）码点。
func unescapeUnicodeEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == '\\' { // 字面反斜杠（已转义），原样保留
				b.WriteString("\\\\")
				i += 2
				continue
			}
			if s[i+1] == 'U' && i+10 <= len(s) {
				if code, err := strconv.ParseUint(s[i+2:i+10], 16, 32); err == nil && code > 0xFFFF {
					b.WriteRune(rune(code))
					i += 10
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// writeYAMLSection 以缩进 2 序列化一个 yaml.Node 并写入缓冲。
// 节点树中的双引号样式（DoubleQuotedStyle）会原样保留到输出文本。
func writeYAMLSection(buf *bytes.Buffer, node *yaml.Node) error {
	var section bytes.Buffer
	enc := yaml.NewEncoder(&section)
	enc.SetIndent(2)
	if err := enc.Encode(node); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	s := section.String()
	// Encode 会为顶层序列额外缩进两格，去掉以贴合手工写入的段头
	s = strings.TrimPrefix(s, "\n")
	buf.WriteString(s)
	if !strings.HasSuffix(s, "\n") {
		buf.WriteString("\n")
	}
	return nil
}

// ---------- yaml.Node 构造助手 ----------

// strNode 普通字符串标量（由 yaml.v3 自动决定是否需要引号）。
func strNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

// quotedStrNode 强制双引号字符串标量。
// 用于 REALITY short-id / 纯数字密码等裸值会被下游 YAML 解析器
// 误判为数值（如 29845e28 被解析为科学计数法浮点数）的场景。
func quotedStrNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v, Style: yaml.DoubleQuotedStyle}
}

// intNode 整数标量。
func intNode(v int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(v)}
}

// boolNode 布尔标量。
func boolNode(v bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(v)}
}

// mapNode 构造空 mapping 节点。
func mapNode() *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode}
}

// setField 向 mapping 追加键值对（非空才写入时由调用方判断）。
func setField(m *yaml.Node, key string, val *yaml.Node) {
	m.Content = append(m.Content, strNode(key), val)
}

// setStr 非空字符串字段。
func setStr(m *yaml.Node, key, val string) {
	if val != "" {
		setField(m, key, strNode(val))
	}
}

// setInt 非零整数字段。
func setInt(m *yaml.Node, key string, val int) {
	if val != 0 {
		setField(m, key, intNode(val))
	}
}

// setBoolTrue 仅在 true 时输出的布尔字段。
func setBoolTrue(m *yaml.Node, key string, val bool) {
	if val {
		setField(m, key, boolNode(val))
	}
}

// setUDP 三态 UDP：nil 不输出，非 nil 输出显式值。
func setUDP(m *yaml.Node, udp *bool) {
	if udp != nil {
		setField(m, "udp", boolNode(*udp))
	}
}

// setALPN 非空 ALPN 序列字段。
func setALPN(m *yaml.Node, alpn []string) {
	if len(alpn) == 0 {
		return
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, a := range alpn {
		seq.Content = append(seq.Content, strNode(a))
	}
	setField(m, "alpn", seq)
}

// ---------- 节点渲染 ----------

// renderProxy 按协议渲染单个节点为 mapping。
// 所有字段遵循"未设置不输出"；UDP 三态；REALITY 关键字段强制引号。
func renderProxy(p *model.Proxy) (*yaml.Node, error) {
	switch p.Type {
	case model.TypeVLESS:
		return renderVLESS(p), nil
	case model.TypeVMess:
		return renderVMess(p), nil
	case model.TypeSS:
		return renderSS(p), nil
	case model.TypeTrojan:
		return renderTrojan(p), nil
	case model.TypeHysteria2:
		return renderHysteria2(p), nil
	case model.TypeAnyTLS:
		return renderAnyTLS(p), nil
	default:
		return nil, fmt.Errorf("不支持的协议类型 %v", p.Type)
	}
}

// renderVLESS 渲染 vless（含 REALITY）节点。
func renderVLESS(p *model.Proxy) *yaml.Node {
	m := mapNode()
	setStr(m, "name", p.Name)
	setField(m, "type", strNode("vless"))
	setStr(m, "server", p.Server)
	setField(m, "port", intNode(p.Port))
	setStr(m, "uuid", p.UUID)
	setStr(m, "flow", p.Flow)
	setBoolTrue(m, "tls", p.TLSSecure)
	setStr(m, "servername", p.SNI)
	setTransport(m, p)
	// REALITY：public-key 为空则整个 reality-opts 不输出；
	// short-id 一律双引号（裸 29845e28 会被下游解析为浮点数），为空时只输出 public-key
	if p.PublicKey != "" {
		ro := mapNode()
		setField(ro, "public-key", strNode(p.PublicKey))
		if sid := p.ShortID; sid != "" {
			setField(ro, "short-id", quotedStrNode(sid))
		}
		setField(m, "reality-opts", ro)
		// REALITY 需要 uTLS 指纹；C++ 在无显式值时兜底 "random"
		if p.ClientFingerprint != "" {
			setStr(m, "client-fingerprint", p.ClientFingerprint)
		} else if p.Fingerprint != "" {
			setStr(m, "client-fingerprint", p.Fingerprint)
		} else {
			setStr(m, "client-fingerprint", "random")
		}
	} else if p.ClientFingerprint != "" {
		setStr(m, "client-fingerprint", p.ClientFingerprint)
	}
	setBoolTrue(m, "skip-cert-verify", p.SkipCertVerify)
	setALPN(m, p.ALPN)
	setUDP(m, p.UDP)
	return m
}

// renderVMess 渲染 vmess 节点。
func renderVMess(p *model.Proxy) *yaml.Node {
	m := mapNode()
	setStr(m, "name", p.Name)
	setField(m, "type", strNode("vmess"))
	setStr(m, "server", p.Server)
	setField(m, "port", intNode(p.Port))
	setStr(m, "uuid", p.UUID)
	setField(m, "alterId", intNode(p.AlterID))
	setStr(m, "cipher", p.Security)
	setBoolTrue(m, "tls", p.TLSSecure)
	setStr(m, "servername", p.SNI)
	setTransport(m, p)
	setBoolTrue(m, "skip-cert-verify", p.SkipCertVerify)
	setALPN(m, p.ALPN)
	setUDP(m, p.UDP)
	return m
}

// renderSS 渲染 shadowsocks 节点。
func renderSS(p *model.Proxy) *yaml.Node {
	m := mapNode()
	setStr(m, "name", p.Name)
	setField(m, "type", strNode("ss"))
	setStr(m, "server", p.Server)
	setField(m, "port", intNode(p.Port))
	setStr(m, "cipher", p.Cipher)
	setPasswordField(m, "password", p.Password)
	setUDP(m, p.UDP)
	return m
}

// renderTrojan 渲染 trojan 节点。
func renderTrojan(p *model.Proxy) *yaml.Node {
	m := mapNode()
	setStr(m, "name", p.Name)
	setField(m, "type", strNode("trojan"))
	setStr(m, "server", p.Server)
	setField(m, "port", intNode(p.Port))
	setPasswordField(m, "password", p.Password)
	setStr(m, "sni", p.SNI)
	setTransport(m, p)
	setBoolTrue(m, "skip-cert-verify", p.SkipCertVerify)
	setALPN(m, p.ALPN)
	setUDP(m, p.UDP)
	return m
}

// renderHysteria2 渲染 hysteria2 节点（字段对齐 mihomo：password/obfs/obfs-password/sni/alpn/skip-cert-verify/ports）。
func renderHysteria2(p *model.Proxy) *yaml.Node {
	m := mapNode()
	setStr(m, "name", p.Name)
	setField(m, "type", strNode("hysteria2"))
	setStr(m, "server", p.Server)
	setField(m, "port", intNode(p.Port))
	setPasswordField(m, "password", p.Password)
	setStr(m, "ports", p.Hysteria2Ports)
	setStr(m, "obfs", p.Hysteria2Obfs)
	setPasswordField(m, "obfs-password", p.Hysteria2ObfsPassword)
	setStr(m, "sni", p.SNI)
	setBoolTrue(m, "skip-cert-verify", p.SkipCertVerify)
	setALPN(m, p.ALPN)
	setUDP(m, p.UDP)
	return m
}

// renderAnyTLS 渲染 anytls 节点。
func renderAnyTLS(p *model.Proxy) *yaml.Node {
	m := mapNode()
	setStr(m, "name", p.Name)
	setField(m, "type", strNode("anytls"))
	setStr(m, "server", p.Server)
	setField(m, "port", intNode(p.Port))
	setPasswordField(m, "password", p.Password)
	setStr(m, "sni", p.SNI)
	setStr(m, "client-fingerprint", p.ClientFingerprint)
	setBoolTrue(m, "skip-cert-verify", p.SkipCertVerify)
	setALPN(m, p.ALPN)
	setUDP(m, p.UDP)
	return m
}

// setPasswordField 输出密码字段；纯数字密码强制双引号，
// 否则裸值会被 go-yaml 解析为整数导致认证失败（C++ looksNumericToGoYaml 同源问题）。
func setPasswordField(m *yaml.Node, key, password string) {
	if password == "" {
		return
	}
	if isAllDigits(password) {
		setField(m, key, quotedStrNode(password))
	} else {
		setField(m, key, strNode(password))
	}
}

// isAllDigits 判断是否纯数字（会被 YAML 解析为整数的密码形态）。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// setTransport 按 Network 输出传输层字段：network 仅在非 tcp 时输出
// （对齐 C++：tcp 不写 network 字段），并跟随 ws-opts / grpc-opts / h2-opts / http-opts。
func setTransport(m *yaml.Node, p *model.Proxy) {
	switch p.Network {
	case "ws":
		setField(m, "network", strNode("ws"))
		ws := mapNode()
		setStr(ws, "path", p.WSPath)
		if len(p.WSHeaders) > 0 {
			headers := mapNode()
			for k, v := range p.WSHeaders {
				if v != "" {
					setStr(headers, k, v)
				}
			}
			if len(headers.Content) > 0 {
				setField(ws, "headers", headers)
			}
		}
		if len(ws.Content) > 0 {
			setField(m, "ws-opts", ws)
		}
	case "grpc":
		setField(m, "network", strNode("grpc"))
		grpc := mapNode()
		setStr(grpc, "grpc-service-name", p.GRPCServiceName)
		setStr(grpc, "grpc-mode", p.GRPCMode)
		if len(grpc.Content) > 0 {
			setField(m, "grpc-opts", grpc)
		}
	case "h2":
		setField(m, "network", strNode("h2"))
		h2 := mapNode()
		setStr(h2, "path", p.WSPath)
		if host := p.WSHeaders["Host"]; host != "" {
			hostSeq := &yaml.Node{Kind: yaml.SequenceNode}
			hostSeq.Content = append(hostSeq.Content, strNode(host))
			setField(h2, "host", hostSeq)
		}
		if len(h2.Content) > 0 {
			setField(m, "h2-opts", h2)
		}
	case "http":
		setField(m, "network", strNode("http"))
		http := mapNode()
		setField(http, "method", strNode("GET"))
		if p.WSPath != "" {
			pathSeq := &yaml.Node{Kind: yaml.SequenceNode}
			pathSeq.Content = append(pathSeq.Content, strNode(p.WSPath))
			setField(http, "path", pathSeq)
		}
		if host := p.WSHeaders["Host"]; host != "" {
			headers := mapNode()
			hostSeq := &yaml.Node{Kind: yaml.SequenceNode}
			hostSeq.Content = append(hostSeq.Content, strNode(host))
			setField(headers, "Host", hostSeq)
			setField(http, "headers", headers)
		}
		setField(m, "http-opts", http)
	}
}

// sanitizeNodeNames 节点名清洗（原地）：
//   - '=' 替换为 '-'（Surge 等客户端对备注中的 '=' 解析异常，对齐 C++ processRemark）
//   - 重名追加 " 2"/" 3" 后缀去重（mihomo 拒绝加载重名节点）
func sanitizeNodeNames(nodes []model.Proxy) {
	seen := make(map[string]int, len(nodes))
	for i := range nodes {
		name := strings.ReplaceAll(nodes[i].Name, "=", "-")
		if cnt, ok := seen[name]; ok {
			seen[name] = cnt + 1
			name = fmt.Sprintf("%s %d", name, cnt+1)
		} else {
			seen[name] = 1
		}
		nodes[i].Name = name
	}
}
