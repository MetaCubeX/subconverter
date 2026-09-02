package parser

import (
	"testing"

	"subconv/internal/model"
)

// TestAnyTLSBasic 标准形态正例。
func TestAnyTLSBasic(t *testing.T) {
	link := "anytls://anypass@2.2.2.2:443?insecure=1&sni=tls.example.com&alpn=h2,http/1.1#anytls%E8%8A%82%E7%82%B9"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Type != model.TypeAnyTLS {
		t.Errorf("Type = %v, want anytls", node.Type)
	}
	if node.Password != "anypass" {
		t.Errorf("Password = %q", node.Password)
	}
	if node.Server != "2.2.2.2" || node.Port != 443 {
		t.Errorf("server/port = %q/%d", node.Server, node.Port)
	}
	if !node.TLSSecure {
		t.Errorf("anytls 应恒为 TLSSecure=true")
	}
	if !node.SkipCertVerify {
		t.Errorf("insecure=1 应置 SkipCertVerify=true")
	}
	if node.SNI != "tls.example.com" {
		t.Errorf("SNI = %q", node.SNI)
	}
	if len(node.ALPN) != 2 || node.ALPN[0] != "h2" || node.ALPN[1] != "http/1.1" {
		t.Errorf("ALPN = %v", node.ALPN)
	}
	if node.Name != "anytls节点" {
		t.Errorf("Name = %q, want anytls节点", node.Name)
	}
}

// TestAnyTLSPeerFallback C++ explodeStdAnyTLS 的 sni 参数实为 peer，
// 两种写法都应识别。
func TestAnyTLSPeerFallback(t *testing.T) {
	node, err := ParseLink("anytls://pw@1.2.3.4:8443?peer=peer.example.com")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.SNI != "peer.example.com" {
		t.Errorf("SNI 应回退读 peer 参数, got %q", node.SNI)
	}
	if node.Name != "1.2.3.4:8443" {
		t.Errorf("缺省名称应为 host:port, got %q", node.Name)
	}
	if node.SkipCertVerify {
		t.Errorf("未传 insecure 时 SkipCertVerify 应为 false")
	}
	if _, err := ParseLink("anytls://only-host:443"); err == nil {
		t.Errorf("缺密码应解析失败")
	}
}
