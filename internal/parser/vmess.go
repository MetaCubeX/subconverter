package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"subconv/internal/model"
)

// vmessJSON vmess:// 链接 base64 解码后的 JSON 结构。
// port/aid/tls 在野外链接中既有数字也有字符串写法，统一用 any 接收
// 再经 anyToInt / anyToBool 归一。
type vmessJSON struct {
	V        string `json:"v"`
	Ps       string `json:"ps"`
	Add      string `json:"add"`
	Port     any    `json:"port"`
	ID       string `json:"id"`
	Aid      any    `json:"aid"`
	Net      string `json:"net"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	TLS      any    `json:"tls"`
	SNI      string `json:"sni"`
	ALPN     string `json:"alpn"`
	Security string `json:"security"`
}

// parseVMess 解析 vmess://base64(JSON) 链接，参考 C++ 版 explodeVmess。
// 字段：ps/add/port/id/aid/net/type/host/path/tls/sni/alpn/security。
// 历史变体：v=1 时 host 可写作 "host;path"（分号拼接）；
// v=2 时 path 独立成字段。解码或 JSON 解析失败均返回 error。
func parseVMess(link string) (*model.Proxy, error) {
	payload := strings.TrimPrefix(link, "vmess://")
	data, err := base64DecodeAny(payload)
	if err != nil {
		return nil, fmt.Errorf("vmess base64 解码失败: %w", err)
	}

	var raw vmessJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("vmess JSON 解析失败: %w", err)
	}

	port, ok := anyToInt(raw.Port)
	if !ok || port == 0 {
		return nil, fmt.Errorf("vmess 链接缺少合法端口: %v", raw.Port)
	}
	add := strings.TrimSpace(raw.Add)
	if add == "" {
		return nil, fmt.Errorf("vmess 链接缺少服务器地址")
	}

	host, path := raw.Host, raw.Path
	switch raw.V {
	case "", "1":
		// v1 变体：host 字段为 "host;path" 两段（仅恰好两段时才拆）
		if parts := strings.Split(host, ";"); len(parts) == 2 {
			host, path = parts[0], parts[1]
		}
	case "2":
		// v2：path 独立字段，无需处理
	}

	network := raw.Net
	if network == "" {
		network = "tcp"
	}

	node := &model.Proxy{
		Type:     model.TypeVMess,
		Name:     raw.Ps,
		Server:   add,
		Port:     port,
		UUID:     raw.ID,
		Network:  network,
		SNI:      raw.SNI,
		Security: raw.Security,
	}
	if node.UUID == "" {
		// C++ vmessConstruct 的缺省 UUID
		node.UUID = "00000000-0000-0000-0000-000000000000"
	}
	if aid, ok := anyToInt(raw.Aid); ok {
		node.AlterID = aid
	}
	if node.Security == "" {
		node.Security = "auto"
	}

	switch network {
	case "ws", "h2", "http":
		if path != "" {
			node.WSPath = strings.TrimSpace(path)
		}
		if host != "" {
			node.WSHeaders = map[string]string{"Host": strings.TrimSpace(host)}
		}
	case "grpc":
		// vmess JSON 的 grpc 服务名复用 path 字段
		node.GRPCServiceName = strings.TrimSpace(path)
	}

	// tls 字段："tls" 字符串或 true 布尔均视为开启
	if s, ok := raw.TLS.(string); ok {
		node.TLSSecure = s == "tls"
	} else if b, ok := raw.TLS.(bool); ok {
		node.TLSSecure = b
	}

	node.ALPN = splitALPN(raw.ALPN)

	if node.Name == "" {
		node.Name = defaultName(add, port)
	}
	return node, nil
}

// anyToInt 归一化 JSON 中的整数字段：兼容 number 与字符串两种写法。
func anyToInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		return i, err == nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

func init() {
	register(parseVMess, "vmess")
}
