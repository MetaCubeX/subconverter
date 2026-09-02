package parser

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"subconv/internal/model"
)

// expectedSIDs testdata/subscription.txt 中 23 个节点的 SID 依次值
// （与任务给定顺序一致；其中三个 29845e28 即"科学计数法形态"回归用例，
// 第 2 个 40452118 为偶数 hex 保留用例）。
var expectedSIDs = []string{
	"18837b24", "40452118", "b6b1ec4e", "d3c6377d", "d3c6377d",
	"fa4081e0", "d3e29581", "10baf868", "cd3b80a9", "1faf1a45",
	"1faf1a45", "bd5681a3", "bd5681a3", "2183bf03", "f22a144c",
	"68a77d69", "2a038621", "2a038621", "29845e28", "29845e28",
	"29845e28", "dd2f4764", "dd2f4764",
}

// TestSubscriptionRealitySample 解析 testdata/subscription.txt：
// 23 个 vless REALITY 节点全部成功，SID 全量比对，
// 29845e28（科学计数法形态）与 40452118 原值保留，REALITY 字段正确。
func TestSubscriptionRealitySample(t *testing.T) {
	data, err := os.ReadFile("../../testdata/subscription.txt")
	if err != nil {
		t.Fatalf("读取测试样本失败: %v", err)
	}
	nodes, err := ParseSubscription(string(data))
	if err != nil {
		t.Fatalf("解析订阅失败: %v", err)
	}
	if len(nodes) != 23 {
		t.Fatalf("节点数 = %d, want 23", len(nodes))
	}

	for i, node := range nodes {
		if node.Type != model.TypeVLESS {
			t.Errorf("节点 %d: Type = %v, want vless", i, node.Type)
		}
		wantServer := "1.2.3." + strconv.Itoa(i+1)
		if node.Server != wantServer {
			t.Errorf("节点 %d: Server = %q, want %q", i+1, node.Server, wantServer)
		}
		if node.Port != 443 {
			t.Errorf("节点 %d: Port = %d, want 443", i+1, node.Port)
		}
		wantName := "节点" + pad2(i+1)
		if node.Name != wantName {
			t.Errorf("节点 %d: Name = %q, want %q", i+1, node.Name, wantName)
		}
		if node.ShortID != expectedSIDs[i] {
			t.Errorf("节点 %d: ShortID = %q, want 原值 %q", i+1, node.ShortID, expectedSIDs[i])
		}
	}

	// 专项回归：三个 29845e28（1-based 第 19/20/21 个）与第 2 个 40452118
	// 的 ShortID 必须原值保留（任务文中写作"第 20/21/22 个"，按给定 SID
	// 顺序实际位于 19/20/21，此处按值断言）
	for _, idx := range []int{18, 19, 20} { // 0-based
		if nodes[idx].ShortID != "29845e28" {
			t.Errorf("第 %d 个节点 ShortID = %q, want 29845e28 原值", idx+1, nodes[idx].ShortID)
		}
	}
	if nodes[1].ShortID != "40452118" {
		t.Errorf("第 2 个节点 ShortID = %q, want 40452118 原值", nodes[1].ShortID)
	}

	// REALITY 公共字段抽一个节点全量校验
	first := nodes[0]
	if first.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("UUID = %q", first.UUID)
	}
	if first.PublicKey != "TestPublicKey1234567890" {
		t.Errorf("PublicKey = %q", first.PublicKey)
	}
	if first.ClientFingerprint != "chrome" {
		t.Errorf("ClientFingerprint = %q", first.ClientFingerprint)
	}
	if first.SNI != "www.microsoft.com" {
		t.Errorf("SNI = %q", first.SNI)
	}
	if first.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q", first.Flow)
	}
	if !first.TLSSecure {
		t.Errorf("security=reality 应置 TLSSecure=true")
	}
	if first.Network != "tcp" {
		t.Errorf("Network = %q", first.Network)
	}
}

// TestSubscriptionPlainTextLines 明文多行订阅：跳过空行与无法识别行。
func TestSubscriptionPlainTextLines(t *testing.T) {
	content := strings.Join([]string{
		"vless://u-1@1.2.3.4:443?security=reality&type=tcp",
		"",
		"这是一行垃圾内容",
		"trojan://pw@5.6.7.8:443?sni=a.com",
		"ss://" + b64raw("aes-128-gcm:pw") + "@7.8.9.0:8388",
		"未知的scheme://xxx",
	}, "\n")
	nodes, err := ParseSubscription(content)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("节点数 = %d, want 3（垃圾行应被跳过）", len(nodes))
	}
	if nodes[0].Type != model.TypeVLESS || nodes[1].Type != model.TypeTrojan || nodes[2].Type != model.TypeSS {
		t.Errorf("节点类型顺序错误: %v, %v, %v", nodes[0].Type, nodes[1].Type, nodes[2].Type)
	}
}

// TestSubscriptionBase64 base64 订阅（标准与 URL-safe 字母表）均应先解码再逐行解析。
func TestSubscriptionBase64(t *testing.T) {
	plain := "vless://u-1@1.2.3.4:443?security=tls&type=tcp#b64a\nhy2://pw@2.3.4.5:443#b64b"
	for name, encoded := range map[string]string{
		"标准字母表":       b64(plain),
		"URL-safe字母表": b64raw(plain),
	} {
		nodes, err := ParseSubscription(encoded)
		if err != nil {
			t.Fatalf("%s: 解析失败: %v", name, err)
		}
		if len(nodes) != 2 {
			t.Fatalf("%s: 节点数 = %d, want 2", name, len(nodes))
		}
		if nodes[0].Name != "b64a" || nodes[1].Name != "b64b" {
			t.Errorf("%s: 节点名错误: %q, %q", name, nodes[0].Name, nodes[1].Name)
		}
	}
}

// TestSubscriptionClashYAML Clash YAML 订阅：常见字段映射 + 未知 type 跳过。
func TestSubscriptionClashYAML(t *testing.T) {
	content := `port: 7890
proxies:
  - name: vm节点
    type: vmess
    server: 1.1.1.1
    port: 443
    uuid: vm-uuid-1
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    servername: cdn.example.com
    udp: true
    ws-opts:
      path: /vmws
      headers:
        Host: cdn.example.com
  - name: reality节点
    type: vless
    server: 2.2.2.2
    port: 443
    uuid: vless-uuid-1
    flow: xtls-rprx-vision
    network: tcp
    tls: true
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: PbKey123
      short-id: 29845e28
  - name: ss节点
    type: ss
    server: 3.3.3.3
    port: 8388
    cipher: aes-128-gcm
    password: sspass
    udp: false
  - name: trojan节点
    type: trojan
    server: 4.4.4.4
    port: 443
    password: tjpass
    sni: tj.example.com
    skip-cert-verify: true
    alpn:
      - h2
      - http/1.1
  - name: hy2节点
    type: hysteria2
    server: 5.5.5.5
    port: 443
    password: hy2pass
    obfs: salamander
    obfs-password: obfs123
    ports: 20000-30000
  - name: anytls节点
    type: anytls
    server: 6.6.6.6
    port: 8443
    password: atpass
    sni: at.example.com
  - name: 不支持的节点
    type: wireguard
    server: 7.7.7.7
    port: 51820
`
	nodes, err := ParseSubscription(content)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(nodes) != 6 {
		t.Fatalf("节点数 = %d, want 6（wireguard 应被跳过）", len(nodes))
	}

	vm := nodes[0]
	if vm.Type != model.TypeVMess || vm.UUID != "vm-uuid-1" || vm.AlterID != 0 {
		t.Errorf("vmess 节点字段错误: %+v", vm)
	}
	if vm.Network != "ws" || vm.WSPath != "/vmws" || vm.WSHeaders["Host"] != "cdn.example.com" {
		t.Errorf("vmess ws-opts 字段错误: %+v", vm)
	}
	if !vm.TLSSecure || vm.SNI != "cdn.example.com" {
		t.Errorf("vmess TLS 字段错误: %+v", vm)
	}
	if vm.UDP == nil || !*vm.UDP {
		t.Errorf("vmess udp: true 应写入三态指针")
	}

	reality := nodes[1]
	if reality.Type != model.TypeVLESS || reality.UUID != "vless-uuid-1" {
		t.Errorf("vless 节点字段错误: %+v", reality)
	}
	if reality.PublicKey != "PbKey123" {
		t.Errorf("reality PublicKey = %q", reality.PublicKey)
	}
	// 关键回归：YAML 裸标量 29845e28 会被 go-yaml 当作科学计数法 float，
	// 必须按原始文本读取（yaml.Node 方案）
	if reality.ShortID != "29845e28" {
		t.Errorf("reality ShortID = %q, want 原始文本 29845e28", reality.ShortID)
	}
	if reality.Flow != "xtls-rprx-vision" || reality.ClientFingerprint != "chrome" {
		t.Errorf("reality flow/fp 字段错误: %+v", reality)
	}

	ss := nodes[2]
	if ss.Type != model.TypeSS || ss.Cipher != "aes-128-gcm" || ss.Password != "sspass" {
		t.Errorf("ss 节点字段错误: %+v", ss)
	}
	if ss.UDP == nil || *ss.UDP {
		t.Errorf("ss udp: false 应写入显式 false")
	}

	tj := nodes[3]
	if tj.Type != model.TypeTrojan || tj.Password != "tjpass" || tj.SNI != "tj.example.com" {
		t.Errorf("trojan 节点字段错误: %+v", tj)
	}
	if !tj.SkipCertVerify {
		t.Errorf("trojan skip-cert-verify: true 未生效")
	}
	if len(tj.ALPN) != 2 || tj.ALPN[0] != "h2" || tj.ALPN[1] != "http/1.1" {
		t.Errorf("trojan ALPN = %v", tj.ALPN)
	}

	hy2 := nodes[4]
	if hy2.Type != model.TypeHysteria2 || hy2.Password != "hy2pass" {
		t.Errorf("hysteria2 节点字段错误: %+v", hy2)
	}
	if hy2.Hysteria2Obfs != "salamander" || hy2.Hysteria2ObfsPassword != "obfs123" || hy2.Hysteria2Ports != "20000-30000" {
		t.Errorf("hysteria2 obfs 字段错误: %+v", hy2)
	}

	at := nodes[5]
	if at.Type != model.TypeAnyTLS || at.Password != "atpass" || at.SNI != "at.example.com" {
		t.Errorf("anytls 节点字段错误: %+v", at)
	}
}

// TestSubscriptionClashProxyKey Surge 风格的 "Proxy:" 键名也应识别。
func TestSubscriptionClashProxyKey(t *testing.T) {
	content := `Proxy:
  - {name: p1, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-128-gcm, password: pw}
  - {name: p2, type: vmess, server: 2.2.2.2, port: 443, uuid: u1, cipher: auto}
`
	nodes, err := ParseSubscription(content)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("节点数 = %d, want 2", len(nodes))
	}
	if nodes[0].Type != model.TypeSS || nodes[1].Type != model.TypeVMess {
		t.Errorf("Proxy: 键名节点类型错误: %v, %v", nodes[0].Type, nodes[1].Type)
	}
}

// TestSubscriptionErrors 反例：空内容、纯垃圾、全部无法识别时返回 error。
func TestSubscriptionErrors(t *testing.T) {
	for name, content := range map[string]string{
		"空内容":     "   ",
		"纯垃圾":     "hello world\nfoo bar",
		"坏base64": "!!!!不是base64也不是链接!!!!",
	} {
		if _, err := ParseSubscription(content); err == nil {
			t.Errorf("%s: 应返回 error", name)
		}
	}
}

// pad2 两位补零（1 → "01"）。
func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
