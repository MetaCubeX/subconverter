package parser

import (
	"encoding/base64"
	"testing"

	"subconv/internal/model"
)

// b64 标准带 padding 编码。
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// b64raw URL-safe 无 padding 编码（机场订阅常见形态）。
func b64raw(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// TestVMessV2 v2 形态正例：base64 JSON、端口字符串写法、ws 传输、tls 开启。
func TestVMessV2(t *testing.T) {
	json := `{"v":"2","ps":"vmess节点","add":"5.6.7.8","port":"443",` +
		`"id":"aaaabbbb-cccc-dddd-eeee-ffff00001111","aid":0,` +
		`"net":"ws","type":"none","host":"cdn.example.com","path":"/vmws",` +
		`"tls":"tls","sni":"cdn.example.com","alpn":"h2,http/1.1","security":"aes-128-gcm"}`
	node, err := ParseLink("vmess://" + b64raw(json))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Type != model.TypeVMess {
		t.Errorf("Type = %v, want vmess", node.Type)
	}
	if node.Name != "vmess节点" || node.Server != "5.6.7.8" || node.Port != 443 {
		t.Errorf("基础字段错误: %+v", node)
	}
	if node.UUID != "aaaabbbb-cccc-dddd-eeee-ffff00001111" {
		t.Errorf("UUID = %q", node.UUID)
	}
	if node.AlterID != 0 {
		t.Errorf("AlterID = %d, want 0", node.AlterID)
	}
	if node.Network != "ws" || node.WSPath != "/vmws" || node.WSHeaders["Host"] != "cdn.example.com" {
		t.Errorf("ws 传输字段错误: %+v", node)
	}
	if !node.TLSSecure {
		t.Errorf("tls 字段应置 TLSSecure=true")
	}
	if node.SNI != "cdn.example.com" {
		t.Errorf("SNI = %q", node.SNI)
	}
	if node.Security != "aes-128-gcm" {
		t.Errorf("Security = %q", node.Security)
	}
	if len(node.ALPN) != 2 || node.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v", node.ALPN)
	}
}

// TestVMessV1HostPath v1 历史变体：host 字段为 "host;path" 两段。
func TestVMessV1HostPath(t *testing.T) {
	json := `{"ps":"v1节点","add":"1.2.3.4","port":8443,"id":"u-1",` +
		`"aid":"0","net":"ws","host":"v1host.example.com;/v1path","tls":""}`
	node, err := ParseLink("vmess://" + b64(json))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.WSHeaders["Host"] != "v1host.example.com" || node.WSPath != "/v1path" {
		t.Errorf("v1 host;path 拆分错误: %+v", node)
	}
	if node.TLSSecure {
		t.Errorf("tls 为空串时不应开启 TLS")
	}
	if node.Security != "auto" {
		t.Errorf("缺省 Security 应为 auto, got %q", node.Security)
	}
	// port/aid 为数字写法也应正常
	if node.Port != 8443 {
		t.Errorf("Port = %d, want 8443", node.Port)
	}
}

// TestVMessDefaults 缺省：名称 host:port、UUID 兜底、net 兜底 tcp。
func TestVMessDefaults(t *testing.T) {
	json := `{"add":"9.8.7.6","port":10086}`
	node, err := ParseLink("vmess://" + b64raw(json))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Name != "9.8.7.6:10086" {
		t.Errorf("缺省名称应为 host:port, got %q", node.Name)
	}
	if node.UUID != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("缺省 UUID 错误: %q", node.UUID)
	}
	if node.Network != "tcp" {
		t.Errorf("缺省 Network 应为 tcp, got %q", node.Network)
	}
}

// TestVMessBadBase64 反例：非法 base64。
func TestVMessBadBase64(t *testing.T) {
	if _, err := ParseLink("vmess://!!!not-base64!!!"); err == nil {
		t.Errorf("非法 base64 应返回 error")
	}
}

// TestVMessBadJSON 反例：base64 合法但内容不是 JSON、端口缺失/为 0。
func TestVMessBadJSON(t *testing.T) {
	if _, err := ParseLink("vmess://" + b64("plain text, not json")); err == nil {
		t.Errorf("非 JSON 内容应返回 error")
	}
	if _, err := ParseLink("vmess://" + b64raw(`{"add":"1.1.1.1","port":0}`)); err == nil {
		t.Errorf("端口 0 应返回 error")
	}
	if _, err := ParseLink("vmess://" + b64raw(`{"port":443}`)); err == nil {
		t.Errorf("缺少服务器地址应返回 error")
	}
}
