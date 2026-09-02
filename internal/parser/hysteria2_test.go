package parser

import (
	"testing"

	"subconv/internal/model"
)

// TestHysteria2SchemeAliases hysteria2:// 与 hy2:// 两个前缀都应分发到同一解析器。
func TestHysteria2SchemeAliases(t *testing.T) {
	for _, scheme := range []string{"hysteria2", "hy2"} {
		link := scheme + "://hy2pass@3.3.3.3:443" +
			"?obfs=salamander&obfs-password=obfs123&sni=hy.example.com&insecure=1&mport=20000-30000" +
			"#%E7%BE%8E%E5%9B%BD01"
		node, err := ParseLink(link)
		if err != nil {
			t.Fatalf("%s 解析失败: %v", scheme, err)
		}
		if node.Type != model.TypeHysteria2 {
			t.Errorf("%s: Type = %v, want hysteria2", scheme, node.Type)
		}
		if node.Password != "hy2pass" {
			t.Errorf("%s: Password = %q", scheme, node.Password)
		}
		if node.Server != "3.3.3.3" || node.Port != 443 {
			t.Errorf("%s: server/port = %q/%d", scheme, node.Server, node.Port)
		}
		if node.Hysteria2Obfs != "salamander" || node.Hysteria2ObfsPassword != "obfs123" {
			t.Errorf("%s: obfs 字段错误: %+v", scheme, node)
		}
		if node.SNI != "hy.example.com" {
			t.Errorf("%s: SNI = %q", scheme, node.SNI)
		}
		if !node.SkipCertVerify {
			t.Errorf("%s: insecure=1 应置 SkipCertVerify=true", scheme)
		}
		if node.Hysteria2Ports != "20000-30000" {
			t.Errorf("%s: Ports = %q", scheme, node.Hysteria2Ports)
		}
		if !node.TLSSecure {
			t.Errorf("%s: hysteria2 应恒为 TLSSecure=true", scheme)
		}
		if node.Name != "美国01" {
			t.Errorf("%s: Name = %q, want 美国01", scheme, node.Name)
		}
	}
}

// TestHysteria2DefaultName 缺省名与最简参数。
func TestHysteria2DefaultName(t *testing.T) {
	node, err := ParseLink("hy2://pw@1.1.1.1:36712")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Name != "1.1.1.1:36712" {
		t.Errorf("缺省名称应为 host:port, got %q", node.Name)
	}
	if node.Hysteria2Obfs != "" || node.SkipCertVerify {
		t.Errorf("缺省时不应设置 obfs/insecure: %+v", node)
	}
	if _, err := ParseLink("hy2://1.1.1.1:443"); err == nil {
		t.Errorf("缺密码应解析失败")
	}
}
