package render

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"subconv/internal/model"
	"subconv/internal/parser"
	"subconv/internal/rule"
)

// clashDoc RenderClash 输出反序列化的通用结构。
type clashDoc struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []map[string]any `yaml:"proxy-groups"`
	Rules   []string         `yaml:"rules"`
}

// loadSampleNodes 解析 testdata/subscription.txt（Phase 1 的 23 个 vless REALITY 样本）。
func loadSampleNodes(t *testing.T) []model.Proxy {
	t.Helper()
	data, err := os.ReadFile("../../testdata/subscription.txt")
	if err != nil {
		t.Fatalf("读取测试样本失败: %v", err)
	}
	nodes, err := parser.ParseSubscription(string(data))
	if err != nil {
		t.Fatalf("解析订阅失败: %v", err)
	}
	if len(nodes) != 23 {
		t.Fatalf("样本节点数 = %d, want 23", len(nodes))
	}
	return nodes
}

// TestRenderClashRealitySample 23 个 REALITY 节点渲染：
// 节点数、short-id 反序列化后为 string 类型且值保留、public-key 存在、尾部 MATCH。
func TestRenderClashRealitySample(t *testing.T) {
	nodes := loadSampleNodes(t)
	out, err := RenderClash(nodes, &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	var doc clashDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("输出不是合法 YAML: %v\n%s", err, out)
	}
	if len(doc.Proxies) != 23 {
		t.Fatalf("proxies 数 = %d, want 23", len(doc.Proxies))
	}

	for i, p := range doc.Proxies {
		if p["type"] != "vless" {
			t.Errorf("节点 %d type = %v, want vless", i, p["type"])
		}
		if p["tls"] != true {
			t.Errorf("节点 %d tls = %v, want true", i, p["tls"])
		}
		ro, ok := p["reality-opts"].(map[string]any)
		if !ok {
			t.Errorf("节点 %d 缺少 reality-opts", i)
			continue
		}
		if ro["public-key"] != "TestPublicKey1234567890" {
			t.Errorf("节点 %d public-key = %v", i, ro["public-key"])
		}
		sid, ok := ro["short-id"]
		if !ok {
			t.Errorf("节点 %d 缺少 short-id", i)
			continue
		}
		// 关键回归：裸 29845e28 会被 go-yaml 解析为浮点数，
		// 双引号强制字符串后此处必须是 string
		if _, isStr := sid.(string); !isStr {
			t.Errorf("节点 %d short-id 类型 = %T, want string", i, sid)
		}
	}
	// 29845e28 的三个节点（0-based 18/19/20）专项验证值保留
	for _, idx := range []int{18, 19, 20} {
		ro := doc.Proxies[idx]["reality-opts"].(map[string]any)
		if ro["short-id"] != "29845e28" {
			t.Errorf("节点 %d short-id = %v, want \"29845e28\"", idx, ro["short-id"])
		}
	}

	// 无 ACL 时 rules 仅有 MATCH 兜底
	if len(doc.Rules) == 0 || !strings.HasPrefix(doc.Rules[len(doc.Rules)-1], "MATCH,") {
		t.Errorf("rules 尾部缺少 MATCH 兜底: %v", doc.Rules)
	}
}

// TestRenderClashShortIDDoubleQuotedText 输出文本层断言：short-id 一律带双引号
// （yaml.Node DoubleQuotedStyle 的直接证据，杜绝裸 29845e28 被下游解析为浮点数）。
func TestRenderClashShortIDDoubleQuotedText(t *testing.T) {
	nodes := loadSampleNodes(t)
	out, err := RenderClash(nodes, &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(out, `short-id: "29845e28"`) {
		t.Errorf("输出应包含 short-id: \"29845e28\"（双引号强制字符串）")
	}
	if !strings.Contains(out, `short-id: "18837b24"`) {
		t.Errorf("普通 hex short-id 也应统一双引号输出: \n%s", out)
	}
	if strings.Contains(out, "short-id: 29845e28") {
		t.Errorf("禁止裸值 short-id（会被解析为浮点数）")
	}
}

// TestRenderClashNoShortIDNode 无 sid 的 REALITY 节点：reality-opts 只含 public-key，不输出 short-id。
func TestRenderClashNoShortIDNode(t *testing.T) {
	nodes := loadSampleNodes(t)
	nodes[0].ShortID = "" // 清空 sid 模拟无 sid 节点
	out, err := RenderClash(nodes, &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	var doc clashDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("输出不是合法 YAML: %v", err)
	}
	ro, ok := doc.Proxies[0]["reality-opts"].(map[string]any)
	if !ok {
		t.Fatal("节点 0 缺少 reality-opts")
	}
	if ro["public-key"] != "TestPublicKey1234567890" {
		t.Errorf("public-key 应保留: %v", ro["public-key"])
	}
	if _, exists := ro["short-id"]; exists {
		t.Errorf("无 sid 节点不应输出 short-id: %v", ro)
	}
	// 其余节点不受影响
	ro1 := doc.Proxies[1]["reality-opts"].(map[string]any)
	if ro1["short-id"] != "40452118" {
		t.Errorf("节点 1 short-id = %v", ro1["short-id"])
	}
}

// TestRenderClashProtocols 各协议字段渲染（vmess/ss/trojan/hysteria2/anytls）。
func TestRenderClashProtocols(t *testing.T) {
	udpTrue, udpFalse := true, false
	nodes := []model.Proxy{
		{
			Type: model.TypeVMess, Name: "vm节点", Server: "1.1.1.1", Port: 443, UUID: "u1",
			AlterID: 0, Security: "auto", Network: "ws", WSPath: "/ws", TLSSecure: true,
			SNI: "cdn.example.com", UDP: &udpTrue,
		},
		{
			Type: model.TypeSS, Name: "ss节点", Server: "2.2.2.2", Port: 8388,
			Cipher: "aes-128-gcm", Password: "123456", UDP: &udpFalse,
		},
		{
			Type: model.TypeTrojan, Name: "tj节点", Server: "3.3.3.3", Port: 443,
			Password: "tjpass", SNI: "tj.example.com", SkipCertVerify: true,
		},
		{
			Type: model.TypeHysteria2, Name: "hy2节点", Server: "4.4.4.4", Port: 443,
			Password: "hy2pass", Hysteria2Obfs: "salamander", Hysteria2ObfsPassword: "654321",
			Hysteria2Ports: "2080:3000", SNI: "hy2.example.com", UDP: &udpTrue,
		},
		{
			Type: model.TypeAnyTLS, Name: "at节点", Server: "5.5.5.5", Port: 8443,
			Password: "atpass", SNI: "at.example.com", ClientFingerprint: "chrome",
		},
	}
	out, err := RenderClash(nodes, &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	var doc clashDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("输出不是合法 YAML: %v\n%s", err, out)
	}
	if len(doc.Proxies) != 5 {
		t.Fatalf("proxies 数 = %d, want 5", len(doc.Proxies))
	}

	vm := doc.Proxies[0]
	if vm["uuid"] != "u1" || vm["cipher"] != "auto" || vm["alterId"] != 0 {
		t.Errorf("vmess 字段错误: %v", vm)
	}
	if vm["tls"] != true || vm["servername"] != "cdn.example.com" {
		t.Errorf("vmess TLS 字段错误: %v", vm)
	}
	if vm["network"] != "ws" {
		t.Errorf("vmess network = %v, want ws", vm["network"])
	}
	ws := vm["ws-opts"].(map[string]any)
	if ws["path"] != "/ws" {
		t.Errorf("vmess ws path = %v", ws["path"])
	}
	if vm["udp"] != true {
		t.Errorf("vmess udp = %v, want true", vm["udp"])
	}

	ss := doc.Proxies[1]
	if ss["cipher"] != "aes-128-gcm" {
		t.Errorf("ss cipher = %v", ss["cipher"])
	}
	// 纯数字密码必须反序列化为 string（双引号强制）
	if pw, ok := ss["password"].(string); !ok || pw != "123456" {
		t.Errorf("ss 纯数字密码应为 string \"123456\", got %T %v", ss["password"], ss["password"])
	}
	if ss["udp"] != false {
		t.Errorf("ss 显式 udp:false = %v, want false", ss["udp"])
	}

	tj := doc.Proxies[2]
	if tj["password"] != "tjpass" || tj["sni"] != "tj.example.com" || tj["skip-cert-verify"] != true {
		t.Errorf("trojan 字段错误: %v", tj)
	}

	hy2 := doc.Proxies[3]
	if hy2["password"] != "hy2pass" || hy2["obfs"] != "salamander" {
		t.Errorf("hysteria2 字段错误: %v", hy2)
	}
	if hy2["ports"] != "2080:3000" {
		t.Errorf("hysteria2 ports = %v", hy2["ports"])
	}
	if obfsPw, ok := hy2["obfs-password"].(string); !ok || obfsPw != "654321" {
		t.Errorf("hysteria2 纯数字 obfs-password 应为 string, got %T %v", hy2["obfs-password"], hy2["obfs-password"])
	}

	at := doc.Proxies[4]
	if at["password"] != "atpass" || at["sni"] != "at.example.com" || at["client-fingerprint"] != "chrome" {
		t.Errorf("anytls 字段错误: %v", at)
	}
}

// TestRenderClashUDPUnset udp 未设置（nil）时不输出该字段。
func TestRenderClashUDPUnset(t *testing.T) {
	nodes := []model.Proxy{
		{Type: model.TypeSS, Name: "n", Server: "1.1.1.1", Port: 8388, Cipher: "aes-128-gcm", Password: "pw"},
	}
	out, err := RenderClash(nodes, &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if strings.Contains(out, "udp") {
		t.Errorf("未设置的 udp 不应输出:\n%s", out)
	}
}

// TestRenderClashNameSanitize 重名节点去重与 '=' 清洗。
func TestRenderClashNameSanitize(t *testing.T) {
	nodes := []model.Proxy{
		{Type: model.TypeSS, Name: "节点=1", Server: "1.1.1.1", Port: 8388, Cipher: "aes-128-gcm", Password: "a"},
		{Type: model.TypeSS, Name: "节点=1", Server: "2.2.2.2", Port: 8388, Cipher: "aes-128-gcm", Password: "b"},
	}
	out, err := RenderClash(nodes, &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	var doc clashDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("输出不是合法 YAML: %v", err)
	}
	if doc.Proxies[0]["name"] != "节点-1" || doc.Proxies[1]["name"] != "节点-1 2" {
		t.Errorf("节点名清洗/去重错误: %v, %v", doc.Proxies[0]["name"], doc.Proxies[1]["name"])
	}
}

// TestUnescapeUnicodeEscapes \U 转义还原：emoji 还原、成对反斜杠的字面文本不误伤。
func TestUnescapeUnicodeEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"\U0001F680 节点选择"`, `"🚀 节点选择"`},
		{`"\\U0001F680"`, `"\\U0001F680"`},               // 字面反斜杠 + U…（被转义的 \ 后接文本）
		{`"\U0001F680\U0001F1E8\U0001F1F3"`, `"🚀🇨🇳"`},    // 连续多个
		{`short-id: "29845e28"`, `short-id: "29845e28"`}, // 不含转义原样
		{`"\u0000"`, `"\u0000"`},                         // BMP 内转义（\u 4 位）不处理
		{`"C:\\path"`, `"C:\\path"`},
	}
	for _, c := range cases {
		if got := unescapeUnicodeEscapes(c.in); got != c.want {
			t.Errorf("unescapeUnicodeEscapes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRenderClashEmojiPlain 组名 emoji 原样输出（不被 \U 转义）。
func TestRenderClashEmojiPlain(t *testing.T) {
	acl := &rule.ACLConfig{Groups: []rule.GroupConfig{
		{Name: "🚀 节点选择", Type: rule.GroupSelect, Items: []string{"[]DIRECT"}},
	}}
	out, err := RenderClash(nil, &Config{ACL: acl})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(out, `name: "🚀 节点选择"`) {
		t.Errorf("组名 emoji 应原样输出（保留引号但不含 \\U 转义）:\n%s", out)
	}
	if strings.Contains(out, `\U0001F680`) {
		t.Errorf("不应残留 \\U 转义:\n%s", out)
	}
}

// TestConvertUnsupportedTarget 不支持的 target 报错；clash 正常分发。
func TestConvertUnsupportedTarget(t *testing.T) {
	if _, err := Convert("surge", nil, &Config{}); err == nil {
		t.Error("不支持的目标格式应返回 error")
	}
	nodes := []model.Proxy{
		{Type: model.TypeSS, Name: "n", Server: "1.1.1.1", Port: 8388, Cipher: "aes-128-gcm", Password: "pw"},
	}
	if out, err := Convert("clash", nodes, &Config{}); err != nil || !strings.Contains(out, "proxies:") {
		t.Errorf("clash 分发失败: %v", err)
	}
}

// TestEndToEndMini 端到端：testdata 样本 → testdata/acl_mini.ini（纯远程
// ruleset + 内联）→ RenderClash。远程规则集用 httptest 供 lan.list 样本，
// 网络失败自动跳过不影响断言；三段齐全 + MATCH 兜底必须成立。
func TestEndToEndMini(t *testing.T) {
	aclData, err := os.ReadFile("../../testdata/acl_mini.ini")
	if err != nil {
		t.Fatalf("读取测试配置失败: %v", err)
	}
	// 把 ini 中 example.com 的远程 ruleset 替换为本地 httptest 地址
	listURL := startListServer(t)
	aclData = []byte(strings.ReplaceAll(string(aclData), "https://example.com/rules/LocalAreaNetwork.list", listURL))
	acl, err := rule.ParseINI(string(aclData))
	if err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}

	nodes := loadSampleNodes(t)
	out, err := RenderClash(nodes, &Config{ACL: acl})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	var doc clashDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("输出不是合法 YAML: %v\n%s", err, out)
	}
	if len(doc.Proxies) != 23 {
		t.Fatalf("proxies 数 = %d, want 23", len(doc.Proxies))
	}
	if len(doc.Groups) != 5 {
		t.Fatalf("proxy-groups 数 = %d, want 5", len(doc.Groups))
	}
	if len(doc.Rules) < 7 {
		// lan.list 5 条 + GEOIP + MATCH ≥ 7（其余 example.com ruleset 网络失败跳过）
		t.Fatalf("rules 数 = %d, want ≥ 7", len(doc.Rules))
	}
	last := doc.Rules[len(doc.Rules)-1]
	if !strings.HasPrefix(last, "MATCH,") {
		t.Errorf("最后一条规则应为 MATCH 兜底, got %q", last)
	}
	// mini ini 的 FINAL 指向 🐟 漏网之鱼
	if last != "MATCH,🐟 漏网之鱼" {
		t.Errorf("MATCH 兜底策略 = %q, want 🐟 漏网之鱼", last)
	}
	// GEOIP 内联规则始终存在（不依赖网络）
	hasGEOIP := false
	for _, r := range doc.Rules {
		if r == "GEOIP,CN,🎯 全球直连" {
			hasGEOIP = true
		}
	}
	if !hasGEOIP {
		t.Errorf("缺少内联规则 GEOIP,CN,🎯 全球直连: %v", doc.Rules)
	}

	// 节点选择组：引用组 + DIRECT + 全部 23 节点展开
	var sel map[string]any
	for _, g := range doc.Groups {
		if g["name"] == "🚀 节点选择" {
			sel = g
		}
	}
	if sel == nil {
		t.Fatal("缺少 🚀 节点选择 组")
	}
	proxies := sel["proxies"].([]any)
	if len(proxies) != 25 { // 自动选择 + DIRECT + 23 节点
		t.Errorf("🚀 节点选择 proxies 数 = %d, want 25（含 23 个节点展开）", len(proxies))
	}

	// 自动选择组为 url-test 且带 url/interval
	var auto map[string]any
	for _, g := range doc.Groups {
		if g["name"] == "♻️ 自动选择" {
			auto = g
		}
	}
	if auto == nil {
		t.Fatal("缺少 ♻️ 自动选择 组")
	}
	if auto["type"] != "url-test" || auto["url"] != "http://www.gstatic.com/generate_204" {
		t.Errorf("自动选择组 type/url 错误: %v", auto)
	}
	if auto["interval"] != 300 {
		t.Errorf("自动选择组 interval = %v, want 300", auto["interval"])
	}
}
