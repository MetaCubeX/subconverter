package parser

import (
	"testing"

	"subconv/internal/model"
)

// TestSSSIP002 标准形态：base64(method:password)@host:port。
func TestSSSIP002(t *testing.T) {
	link := "ss://" + b64raw("aes-128-gcm:test123") + "@9.9.9.9:8388#ss%E8%8A%82%E7%82%B9"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Type != model.TypeSS {
		t.Errorf("Type = %v, want ss", node.Type)
	}
	if node.Cipher != "aes-128-gcm" || node.Password != "test123" {
		t.Errorf("cipher/password = %q/%q", node.Cipher, node.Password)
	}
	if node.Server != "9.9.9.9" || node.Port != 8388 {
		t.Errorf("server/port = %q/%d", node.Server, node.Port)
	}
	if node.Name != "ss节点" {
		t.Errorf("Name = %q, want ss节点", node.Name)
	}
}

// TestSSWithPlugin 带 plugin 参数的变体：解析成功且主体字段不受影响。
func TestSSWithPlugin(t *testing.T) {
	link := "ss://" + b64("chacha20-ietf-poly1305:pw123") +
		"@8.8.8.8:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#ss-plugin"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Cipher != "chacha20-ietf-poly1305" || node.Password != "pw123" {
		t.Errorf("cipher/password = %q/%q", node.Cipher, node.Password)
	}
	if node.Name != "ss-plugin" {
		t.Errorf("Name = %q", node.Name)
	}
}

// TestSSLegacyWholeBase64 旧式形态：整体 base64(method:password@host:port)。
func TestSSLegacyWholeBase64(t *testing.T) {
	link := "ss://" + b64("aes-256-gcm:legacy@7.7.7.7:9999") + "#legacy"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Cipher != "aes-256-gcm" || node.Password != "legacy" {
		t.Errorf("cipher/password = %q/%q", node.Cipher, node.Password)
	}
	if node.Server != "7.7.7.7" || node.Port != 9999 {
		t.Errorf("server/port = %q/%d", node.Server, node.Port)
	}
}

// TestSSPlaintextUserinfo 未做 base64 的明文 method:password userinfo（宽容回退）。
func TestSSPlaintextUserinfo(t *testing.T) {
	node, err := ParseLink("ss://rc4-md5:plainpw@6.6.6.6:8080")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Cipher != "rc4-md5" || node.Password != "plainpw" {
		t.Errorf("cipher/password = %q/%q", node.Cipher, node.Password)
	}
}

// TestSSDefaultName 无 fragment 时缺省名 host:port。
func TestSSDefaultName(t *testing.T) {
	node, err := ParseLink("ss://" + b64raw("aes-128-gcm:pw") + "@5.5.5.5:1234")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Name != "5.5.5.5:1234" {
		t.Errorf("缺省名称应为 host:port, got %q", node.Name)
	}
}

// TestSSErrors 反例：userinfo 无冒号、整体缺 @ 结构、非法端口。
func TestSSErrors(t *testing.T) {
	bad := []string{
		"ss://" + b64raw("no-colon-here") + "@1.2.3.4:443",  // userinfo 无冒号
		"ss://" + b64raw("no structure here"),               // 旧式形态缺 @
		"ss://" + b64raw("aes-128-gcm:pw") + "@1.2.3.4:abc", // 非法端口
	}
	for _, link := range bad {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("链接 %q 应解析失败", link)
		}
	}
}
