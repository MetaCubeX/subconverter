package parser

import (
	"testing"

	"subconv/internal/model"
)

// TestTrojanBasic 标准形态正例。
func TestTrojanBasic(t *testing.T) {
	link := "trojan://tjpass123@4.4.4.4:443?sni=tj.example.com&allowInsecure=1&alpn=h2#%E6%97%A5%E6%9C%AC01"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Type != model.TypeTrojan {
		t.Errorf("Type = %v, want trojan", node.Type)
	}
	if node.Password != "tjpass123" {
		t.Errorf("Password = %q", node.Password)
	}
	if node.Server != "4.4.4.4" || node.Port != 443 {
		t.Errorf("server/port = %q/%d", node.Server, node.Port)
	}
	if !node.TLSSecure {
		t.Errorf("trojan 应恒为 TLSSecure=true")
	}
	if node.SNI != "tj.example.com" {
		t.Errorf("SNI = %q", node.SNI)
	}
	if !node.SkipCertVerify {
		t.Errorf("allowInsecure=1 应置 SkipCertVerify=true")
	}
	if len(node.ALPN) != 1 || node.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v", node.ALPN)
	}
	if node.Name != "日本01" {
		t.Errorf("Name = %q, want 日本01", node.Name)
	}
}

// TestTrojanWS X-ui 风格 type=ws 与 v2rayN 风格 ws=1 两种变体。
func TestTrojanWS(t *testing.T) {
	// X-ui 风格：type=ws&path=...
	ws1, err := ParseLink("trojan://pw@3.3.3.3:443?type=ws&path=%2Ftjws&host=ws.example.com&sni=ws.example.com")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ws1.Network != "ws" || ws1.WSPath != "/tjws" || ws1.WSHeaders["Host"] != "ws.example.com" {
		t.Errorf("ws 传输字段错误: %+v", ws1)
	}

	// v2rayN 风格：ws=1&wspath=...
	ws2, err := ParseLink("trojan://pw@3.3.3.3:8443?ws=1&wspath=%2Ftjws2")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ws2.Network != "ws" || ws2.WSPath != "/tjws2" {
		t.Errorf("ws=1 变体解析错误: %+v", ws2)
	}
}

// TestTrojanDefaultNameAndErrors 缺省名与反例。
func TestTrojanDefaultNameAndErrors(t *testing.T) {
	node, err := ParseLink("trojan://pw@2.2.2.2:443")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Name != "2.2.2.2:443" {
		t.Errorf("缺省名称应为 host:port, got %q", node.Name)
	}
	if node.Network != "tcp" {
		t.Errorf("缺省 Network 应为 tcp, got %q", node.Network)
	}
	for _, link := range []string{
		"trojan://1.2.3.4:443",      // 缺密码
		"trojan://pw@1.2.3.4",       // 缺端口
		"trojan://pw@1.2.3.4:70000", // 端口超范围
	} {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("链接 %q 应解析失败", link)
		}
	}
}
