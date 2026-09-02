package render

import (
	"os"
	"strings"
	"testing"

	"subconv/internal/model"
	"subconv/internal/rule"
)

// loonSectionLines 提取 Loon 输出中指定 [Section] 段的非空行。
func loonSectionLines(t *testing.T, out, section string) []string {
	t.Helper()
	var lines []string
	inSection := false
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "[") {
			inSection = ln == "["+section+"]"
			continue
		}
		if inSection && strings.TrimSpace(ln) != "" {
			lines = append(lines, ln)
		}
	}
	return lines
}

// loonProtocolNodes 六协议测试节点（字段取值与 clash_test.go 的协议用例一致，便于对照）。
func loonProtocolNodes() []model.Proxy {
	return []model.Proxy{
		{
			Type: model.TypeVLESS, Name: "香港01", Server: "1.2.3.4", Port: 443,
			UUID: "11111111-2222-3333-4444-555555555555", Flow: "xtls-rprx-vision",
			PublicKey: "PbKey123", ShortID: "29845e28", SNI: "www.microsoft.com",
			TLSSecure: true, Network: "tcp", ClientFingerprint: "chrome",
		},
		{
			Type: model.TypeVMess, Name: "vm节点", Server: "1.1.1.1", Port: 443, UUID: "u1",
			Security: "auto", Network: "ws", WSPath: "/ws",
			WSHeaders: map[string]string{"Host": "cdn.example.com"},
			TLSSecure: true, SNI: "cdn.example.com",
		},
		{
			Type: model.TypeSS, Name: "ss节点", Server: "2.2.2.2", Port: 8388,
			Cipher: "aes-128-gcm", Password: "123456",
		},
		{
			Type: model.TypeTrojan, Name: "tj节点", Server: "3.3.3.3", Port: 443,
			Password: "tjpass", SNI: "tj.example.com", SkipCertVerify: true,
		},
		{
			Type: model.TypeHysteria2, Name: "hy2节点", Server: "4.4.4.4", Port: 443,
			Password: "hy2pass", Hysteria2Obfs: "salamander", Hysteria2ObfsPassword: "654321",
			SNI: "hy2.example.com",
		},
		{
			Type: model.TypeAnyTLS, Name: "at节点", Server: "5.5.5.5", Port: 8443,
			Password: "atpass", SNI: "at.example.com",
		},
	}
}

// TestRenderLoonProtocols 六协议逐行断言（含 REALITY publicKey/shortId 键名、
// 29845e28 原值不丢、vmess auto→chacha20-ietf-poly1305）。
func TestRenderLoonProtocols(t *testing.T) {
	out, err := RenderLoon(loonProtocolNodes(), &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	wantLines := []string{
		// vless REALITY：uuid 引号、tls/sni/flow/transport 顺序、publicKey/shortId 键名
		`香港01 = vless,1.2.3.4,443,"11111111-2222-3333-4444-555555555555",tls=true,sni=www.microsoft.com,flow=xtls-rprx-vision,transport=tcp,publicKey=PbKey123,shortId=29845e28`,
		// vmess：auto 改写为 chacha20-ietf-poly1305（对齐 C++），ws 传输带 path/host
		`vm节点 = vmess,1.1.1.1,443,chacha20-ietf-poly1305,"u1",over-tls=true,tls-name=cdn.example.com,transport=ws,path=/ws,host=cdn.example.com`,
		// ss：密码加引号
		`ss节点 = Shadowsocks,2.2.2.2,8388,aes-128-gcm,"123456"`,
		// trojan：tls-name + skip-cert-verify
		`tj节点 = trojan,3.3.3.3,443,"tjpass",tls-name=tj.example.com,skip-cert-verify=true`,
		// hysteria2：obfs/obfs-password/sni
		`hy2节点 = hysteria2,4.4.4.4,443,"hy2pass",obfs=salamander,obfs-password=654321,sni=hy2.example.com`,
		// anytls：密码引号 + sni
		`at节点 = anytls,5.5.5.5,8443,"atpass",sni=at.example.com`,
	}
	for _, want := range wantLines {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少节点行:\n%q\n实际输出:\n%s", want, out)
		}
	}

	if proxies := loonSectionLines(t, out, "Proxy"); len(proxies) != 6 {
		t.Errorf("[Proxy] 行数 = %d, want 6: %v", len(proxies), proxies)
	}

	// 29845e28 原值保留（Loon 为纯文本，无 YAML 类型歧义，不加引号）
	if !strings.Contains(out, "shortId=29845e28") {
		t.Errorf("shortId 应原值输出 29845e28")
	}
	if strings.Contains(out, "shortId=\"29845e28\"") {
		t.Errorf("shortId 不应加引号")
	}
}

// TestRenderLoonVLESSTransports vless ws/grpc 传输的键名。
func TestRenderLoonVLESSTransports(t *testing.T) {
	nodes := []model.Proxy{
		{
			Type: model.TypeVLESS, Name: "ws节点", Server: "1.1.1.1", Port: 443, UUID: "u",
			TLSSecure: true, Network: "ws", WSPath: "/path",
			WSHeaders: map[string]string{"Host": "ws.example.com"},
		},
		{
			Type: model.TypeVLESS, Name: "grpc节点", Server: "2.2.2.2", Port: 443, UUID: "u",
			TLSSecure: true, Network: "grpc", GRPCServiceName: "grpcSvc",
		},
	}
	out, err := RenderLoon(nodes, &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(out, `ws节点 = vless,1.1.1.1,443,"u",tls=true,transport=ws,ws-path=/path,ws-headers=Host:ws.example.com`) {
		t.Errorf("vless ws 传输字段错误:\n%s", out)
	}
	if !strings.Contains(out, `grpc节点 = vless,2.2.2.2,443,"u",tls=true,transport=grpc,grpc-service-name=grpcSvc`) {
		t.Errorf("vless grpc 传输字段错误:\n%s", out)
	}
}

// TestRenderLoonSkipUnsupportedTransport vmess h2 传输不支持 → 跳过该节点（对齐 C++ 的 continue）。
func TestRenderLoonSkipUnsupportedTransport(t *testing.T) {
	nodes := []model.Proxy{
		{
			Type: model.TypeVMess, Name: "h2节点", Server: "1.1.1.1", Port: 443, UUID: "u",
			Network: "h2",
		},
		{
			Type: model.TypeSS, Name: "ss节点", Server: "2.2.2.2", Port: 8388,
			Cipher: "aes-128-gcm", Password: "pw",
		},
	}
	out, err := RenderLoon(nodes, &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	proxies := loonSectionLines(t, out, "Proxy")
	if len(proxies) != 1 || !strings.HasPrefix(proxies[0], "ss节点 = Shadowsocks,") {
		t.Errorf("不支持的传输应只跳过对应节点: %v", proxies)
	}
}

// TestRenderLoonSections 段结构：六段头齐全。
func TestRenderLoonSections(t *testing.T) {
	out, err := RenderLoon(loonProtocolNodes()[:1], &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	for _, section := range []string{"[General]", "[Proxy]", "[Remote Proxy]", "[Proxy Group]", "[Rule]", "[Remote Rule]"} {
		if !strings.Contains(out, section) {
			t.Errorf("输出缺少段头 %s:\n%s", section, out)
		}
	}
	// [General] 骨架关键行
	if !strings.Contains(out, "skip-proxy = ") || !strings.Contains(out, "dns-server = ") {
		t.Errorf("[General] 骨架不完整")
	}
}

// TestRenderLoonNoACL 无 ACL 时：无策略组行、规则仅 FINAL 兜底（MATCH 改写）。
func TestRenderLoonNoACL(t *testing.T) {
	out, err := RenderLoon(loonProtocolNodes()[:1], &Config{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if groups := loonSectionLines(t, out, "Proxy Group"); len(groups) != 0 {
		t.Errorf("无 ACL 时不应有策略组: %v", groups)
	}
	rules := loonSectionLines(t, out, "Rule")
	if len(rules) != 1 || rules[0] != "FINAL,DIRECT" {
		t.Errorf("无 ACL 时规则应仅有 FINAL,DIRECT 兜底: %v", rules)
	}
}

// TestRenderLoonEndToEndMini testdata 23 节点 + testdata/acl_mini.ini 端到端：
// 23 行 Proxy、5 行策略组、url-test 组语法、GEOIP 内联规则与 FINAL 兜底。
// 远程 ruleset 中 LocalAreaNetwork 换成 httptest（lan.list 样本），其余网络失败跳过。
func TestRenderLoonEndToEndMini(t *testing.T) {
	aclData, err := os.ReadFile("../../testdata/acl_mini.ini")
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	listURL := startListServer(t)
	aclData = []byte(strings.ReplaceAll(string(aclData), "https://example.com/rules/LocalAreaNetwork.list", listURL))
	acl, err := rule.ParseINI(string(aclData))
	if err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}

	out, err := RenderLoon(loadSampleNodes(t), &Config{ACL: acl})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	proxies := loonSectionLines(t, out, "Proxy")
	if len(proxies) != 23 {
		t.Fatalf("[Proxy] 行数 = %d, want 23", len(proxies))
	}
	if !strings.HasPrefix(proxies[0], "节点01 = vless,1.2.3.1,443,") {
		t.Errorf("首行节点应为 vless: %q", proxies[0])
	}
	if !strings.Contains(proxies[18], "shortId=29845e28") {
		t.Errorf("节点19 应保留 shortId=29845e28: %q", proxies[18])
	}

	groups := loonSectionLines(t, out, "Proxy Group")
	if len(groups) != 5 {
		t.Fatalf("[Proxy Group] 行数 = %d, want 5: %v", len(groups), groups)
	}
	// select 组：成员 = ♻️ 自动选择 + DIRECT + 23 节点 = 25
	var selectLine string
	var urlTestLine string
	for _, g := range groups {
		switch {
		case strings.HasPrefix(g, "🚀 节点选择 = select,"):
			selectLine = g
		case strings.HasPrefix(g, "♻️ 自动选择 = url-test,"):
			urlTestLine = g
		}
	}
	if got := strings.Count(selectLine, ",") + 1; got != 26 { // 类型 + 25 成员（自动选择 + DIRECT + 23 节点）= 26 段
		t.Errorf("🚀 节点选择 成员段数 = %d, want 26: %s", got, selectLine)
	}
	// url-test 尾参：url=...,interval=300,tolerance=50
	for _, want := range []string{
		",url=http://www.gstatic.com/generate_204",
		",interval=300",
		",tolerance=50",
	} {
		if !strings.Contains(urlTestLine, want) {
			t.Errorf("url-test 组缺少 %q: %s", want, urlTestLine)
		}
	}

	rules := loonSectionLines(t, out, "Rule")
	if len(rules) == 0 {
		t.Fatal("[Rule] 为空")
	}
	if last := rules[len(rules)-1]; last != "FINAL,🐟 漏网之鱼" {
		t.Errorf("最后一条规则应为 FINAL,🐟 漏网之鱼, got %q", last)
	}
	hasGEOIP := false
	for _, r := range rules {
		if r == "GEOIP,CN,🎯 全球直连" {
			hasGEOIP = true
		}
		if strings.HasPrefix(r, "MATCH,") {
			t.Errorf("Loon 规则不应出现 MATCH（应为 FINAL）: %q", r)
		}
	}
	if !hasGEOIP {
		t.Errorf("缺少内联规则 GEOIP,CN,🎯 全球直连")
	}
}

// TestRenderLoonLoadBalance load-balance 组的 algorithm 映射
// （consistent-hashing/缺省 → pcc，round-robin → round-robin）。
func TestRenderLoonLoadBalance(t *testing.T) {
	acl := &rule.ACLConfig{Groups: []rule.GroupConfig{
		{Name: "lb默认", Type: rule.GroupLoadBalance, Items: []string{"[]DIRECT"},
			URL: "http://www.gstatic.com/generate_204", Interval: 300},
		{Name: "lb轮询", Type: rule.GroupLoadBalance, Items: []string{"[]DIRECT"},
			URL: "http://www.gstatic.com/generate_204", Interval: 300, Strategy: "round-robin"},
	}}
	out, err := RenderLoon(nil, &Config{ACL: acl})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(out, "lb默认 = load-balance,DIRECT,url=http://www.gstatic.com/generate_204,interval=300,algorithm=pcc") {
		t.Errorf("load-balance 默认策略应为 pcc:\n%s", out)
	}
	if !strings.Contains(out, "lb轮询 = load-balance,DIRECT,url=http://www.gstatic.com/generate_204,interval=300,algorithm=round-robin") {
		t.Errorf("load-balance round-robin 映射错误:\n%s", out)
	}
}

// TestLoonRule MATCH→FINAL 改写单测。
func TestLoonRule(t *testing.T) {
	cases := []struct{ in, want string }{
		{"MATCH,🐟 漏网之鱼", "FINAL,🐟 漏网之鱼"},
		{"DOMAIN-SUFFIX,google.com,🚀 节点选择", "DOMAIN-SUFFIX,google.com,🚀 节点选择"},
		{"GEOIP,CN,🎯 全球直连", "GEOIP,CN,🎯 全球直连"},
	}
	for _, c := range cases {
		if got := loonRule(c.in); got != c.want {
			t.Errorf("loonRule(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
