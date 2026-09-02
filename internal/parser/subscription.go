package parser

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"subconv/internal/model"
)

// ParseSubscription 解析订阅内容，返回节点列表。内容识别顺序：
//
//  1. 含 "proxies:" 或 "Proxy:" 开头行 → 当作 Clash YAML，
//     读 name/type/server/port/uuid/password/cipher 等常见字段映射到 Proxy，
//     遇不认识的 type 跳过该节点
//  2. 否则尝试 base64（标准或 URL-safe）解码，成功且解码后含 "://" → 用解码后内容
//  3. 按行 split（\n，或纯 \r 内容按 \r），逐行 ParseLink，
//     跳过空行和无法识别的行（对齐 C++ explodeSub）
//
// 全部无法解析时返回 error。
func ParseSubscription(content string) ([]model.Proxy, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, fmt.Errorf("订阅内容为空")
	}

	var nodes []model.Proxy
	if hasClashProxiesKey(content) {
		parsed, err := parseClashYAML(content)
		if err != nil {
			return nil, err
		}
		nodes = parsed
	} else {
		// 尝试 base64：解码成功且含 "://" 才采用解码结果，否则按明文处理。
		// 与 C++ 的区别：C++ 宽松解码失败时原样返回，这里用严格解码 + 内容
		// 嗅探，避免明文订阅被半解码成乱码。
		if data, err := base64DecodeAny(content); err == nil {
			if decoded := string(data); strings.Contains(decoded, "://") {
				content = decoded
			}
		}
		nodes = parseLinkLines(content)
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("订阅内容无法解析出任何节点")
	}
	return nodes, nil
}

// hasClashProxiesKey 判断是否含 "proxies:" 或 "Proxy:" 开头行（Clash YAML 标志，
// 对应 C++ regFind("\"?(Proxy|proxies)\"?:")，此处收紧为行首匹配）。
func hasClashProxiesKey(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimLeft(line, " \t\r")
		if strings.HasPrefix(line, "proxies:") || strings.HasPrefix(line, "Proxy:") {
			return true
		}
	}
	return false
}

// parseLinkLines 逐行解析链接列表，跳过空行与无法识别的行。
func parseLinkLines(content string) []model.Proxy {
	sep := "\n"
	// 纯 \r 分隔（无任何 \n）内容的兜底，对齐 C++ 按计数选择分隔符的逻辑
	if !strings.Contains(content, "\n") && strings.Contains(content, "\r") {
		sep = "\r"
	}
	var nodes []model.Proxy
	for _, line := range strings.Split(content, sep) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if node, err := ParseLink(line); err == nil {
			nodes = append(nodes, *node)
		}
	}
	return nodes
}

// clashConfig Clash 订阅顶层结构，proxies 与 Proxy 两种键名均兼容
// （对应 C++ explodeClash 的 section 选择逻辑）。
// 节点保留为 yaml.Node：标量按原始文本读取，从源头规避
// "29845e28" 这类科学计数法形态的 short-id 被解析成 float 的类型歧义
// （C++ 版 yaml-cpp 踩过的坑，见 REWRITE_PLAN §5）。
type clashConfig struct {
	Proxies []yaml.Node `yaml:"proxies"`
	Proxy   []yaml.Node `yaml:"Proxy"`
}

// parseClashYAML 解析 Clash YAML 订阅。
func parseClashYAML(content string) ([]model.Proxy, error) {
	var cfg clashConfig
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, fmt.Errorf("Clash YAML 解析失败: %w", err)
	}
	entries := cfg.Proxies
	if len(entries) == 0 {
		entries = cfg.Proxy
	}
	var nodes []model.Proxy
	for i := range entries {
		m, ok := nodeToAny(&entries[i]).(map[string]any)
		if !ok {
			continue
		}
		if node := clashMapToProxy(m); node != nil {
			nodes = append(nodes, *node)
		}
	}
	return nodes, nil
}

// nodeToAny 把 yaml.Node 递归转为通用值：映射 → map[string]any，
// 序列 → []any，标量 → 原始文本字符串（null → nil，别名 → 解引用）。
// 标量不做类型推断，是本实现与 C++ 版的关键差异。
func nodeToAny(n *yaml.Node) any {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			return nodeToAny(n.Content[0])
		}
		return nil
	case yaml.AliasNode:
		if n.Alias != nil {
			return nodeToAny(n.Alias)
		}
		return nil
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = nodeToAny(n.Content[i+1])
		}
		return m
	case yaml.SequenceNode:
		list := make([]any, 0, len(n.Content))
		for _, item := range n.Content {
			list = append(list, nodeToAny(item))
		}
		return list
	default:
		if n.Tag == "!!null" {
			return nil
		}
		return n.Value
	}
}

// clashMapToProxy 把单个 Clash 节点 map 映射为 Proxy；不认识的 type 或
// 缺 server/port 的节点返回 nil（跳过，对齐 C++ explodeClash 的 continue）。
func clashMapToProxy(m map[string]any) *model.Proxy {
	server := clashStr(m, "server")
	port, portOK := clashInt(m, "port")
	if server == "" || !portOK || port == 0 {
		return nil
	}

	node := &model.Proxy{
		Name:   clashStr(m, "name"),
		Server: server,
		Port:   port,
	}
	if node.Name == "" {
		node.Name = defaultName(server, port)
	}
	if udp, ok := clashBool(m, "udp"); ok {
		node.UDP = model.BoolPtr(udp)
	}
	if scv, ok := clashBool(m, "skip-cert-verify"); ok {
		node.SkipCertVerify = scv
	}
	node.ALPN = clashALPN(m)
	node.ClientFingerprint = clashStr(m, "client-fingerprint")
	sni := firstNonEmpty(clashStr(m, "sni"), clashStr(m, "servername"))

	switch strings.ToLower(clashStr(m, "type")) {
	case "vmess":
		node.Type = model.TypeVMess
		node.UUID = clashStr(m, "uuid")
		node.Security = firstNonEmpty(clashStr(m, "cipher"), "auto")
		if aid, ok := clashInt(m, "alterId", "alter-id"); ok {
			node.AlterID = aid
		}
		node.Network = firstNonEmpty(clashStr(m, "network"), "tcp")
		node.SNI = sni
		node.TLSSecure, _ = clashBool(m, "tls")
		applyTransport(node, m)
	case "vless":
		node.Type = model.TypeVLESS
		node.UUID = clashStr(m, "uuid")
		node.Flow = clashStr(m, "flow")
		node.Network = firstNonEmpty(clashStr(m, "network"), "tcp")
		node.SNI = sni
		node.TLSSecure, _ = clashBool(m, "tls")
		if ro := clashSubMap(m, "reality-opts"); ro != nil {
			node.PublicKey = clashStr(ro, "public-key")
			node.ShortID = clashStr(ro, "short-id")
			// 配了 REALITY 即视为 TLS（mihomo 语义上 REALITY 必须开 TLS）
			node.TLSSecure = true
		}
		applyTransport(node, m)
	case "ss":
		node.Type = model.TypeSS
		node.Cipher = clashStr(m, "cipher")
		node.Password = clashStr(m, "password")
		if node.Cipher == "" {
			return nil
		}
	case "trojan":
		node.Type = model.TypeTrojan
		node.Password = clashStr(m, "password")
		node.Network = firstNonEmpty(clashStr(m, "network"), "tcp")
		node.SNI = sni
		node.TLSSecure = true
		applyTransport(node, m)
	case "hysteria2":
		node.Type = model.TypeHysteria2
		node.Password = clashStr(m, "password")
		node.Hysteria2Obfs = clashStr(m, "obfs")
		node.Hysteria2ObfsPassword = clashStr(m, "obfs-password")
		node.Hysteria2Ports = clashStr(m, "ports")
		node.SNI = sni
		node.TLSSecure = true
	case "anytls":
		node.Type = model.TypeAnyTLS
		node.Password = clashStr(m, "password")
		node.SNI = sni
		node.TLSSecure = true
	default:
		// 不认识的 type：跳过该节点
		return nil
	}
	return node
}

// applyTransport 按 Network 读取 Clash 传输层选项。
func applyTransport(node *model.Proxy, m map[string]any) {
	switch node.Network {
	case "ws":
		node.WSPath, node.WSHeaders = clashWSOpts(m)
	case "grpc":
		if opts := clashSubMap(m, "grpc-opts"); opts != nil {
			node.GRPCServiceName = clashStr(opts, "grpc-service-name")
			node.GRPCMode = firstNonEmpty(clashStr(opts, "grpc-mode"), "gun")
		}
	case "h2":
		if opts := clashSubMap(m, "h2-opts"); opts != nil {
			node.WSPath = clashStr(opts, "path")
			node.WSHeaders = map[string]string{"Host": clashFirstStr(opts, "host")}
		}
	case "http":
		if opts := clashSubMap(m, "http-opts"); opts != nil {
			node.WSPath = clashFirstStr(opts, "path")
			if headers := clashSubMap(opts, "headers"); headers != nil {
				node.WSHeaders = map[string]string{"Host": clashFirstStr(headers, "Host")}
			}
		}
	}
}

// clashWSOpts 读 WebSocket 选项，兼容新旧两代字段名：
// ws-opts.{path,headers} 与 ws-path/ws-headers（对齐 C++ explodeClash）。
func clashWSOpts(m map[string]any) (path string, headers map[string]string) {
	if opts := clashSubMap(m, "ws-opts"); opts != nil {
		path = clashStr(opts, "path")
		if h := clashSubMap(opts, "headers"); h != nil {
			headers = mapStr(h)
		}
		return
	}
	path = clashStr(m, "ws-path")
	if h := clashSubMap(m, "ws-headers"); h != nil {
		headers = mapStr(h)
	}
	return
}

// clashStr 按键顺序取第一个存在的标量字符串。
func clashStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			return s
		}
	}
	return ""
}

// clashFirstStr 取序列字段的首个字符串元素（如 h2-opts.host / http-opts.path）。
func clashFirstStr(m map[string]any, key string) string {
	if list, ok := m[key].([]any); ok && len(list) > 0 {
		if s, ok := list[0].(string); ok {
			return s
		}
	}
	return ""
}

// clashInt 取整数值（标量已归一为字符串，Atoi 即可）。
func clashInt(m map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// clashBool 取布尔值（true/false/yes/no/on/off 及数字写法），键不存在时 ok=false。
func clashBool(m map[string]any, key string) (val, ok bool) {
	s, exists := m[key].(string)
	if !exists {
		return false, false
	}
	switch strings.ToLower(s) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	}
	return parseBoolParam(s), true
}

// clashSubMap 取子 map（如 ws-opts / reality-opts），不存在返回 nil。
func clashSubMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

// clashALPN 读 alpn 字段：序列或逗号分隔字符串均可。
func clashALPN(m map[string]any) []string {
	switch val := m["alpn"].(type) {
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	case string:
		return splitALPN(val)
	}
	return nil
}

// mapStr 把 map[string]any 归一为 map[string]string（仅保留字符串值）。
func mapStr(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
