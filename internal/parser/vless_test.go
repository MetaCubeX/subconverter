package parser

import (
	"testing"

	"subconv/internal/model"
)

// TestVLESSReality 全参数 REALITY 正例（tuotuoyun 订阅典型形态）。
func TestVLESSReality(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443" +
		"?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome" +
		"&pbk=TestPublicKey1234567890&sid=29845e28&type=tcp&flow=xtls-rprx-vision" +
		"#%E9%A6%99%E6%B8%AF01"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Type != model.TypeVLESS {
		t.Errorf("Type = %v, want vless", node.Type)
	}
	if node.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("UUID = %q", node.UUID)
	}
	if node.Server != "1.2.3.4" || node.Port != 443 {
		t.Errorf("Server/Port = %q/%d", node.Server, node.Port)
	}
	if node.Name != "香港01" {
		t.Errorf("Name = %q, want 香港01（fragment 应 URL 解码）", node.Name)
	}
	if !node.TLSSecure {
		t.Errorf("security=reality 应置 TLSSecure=true")
	}
	if node.SNI != "www.microsoft.com" {
		t.Errorf("SNI = %q", node.SNI)
	}
	if node.ClientFingerprint != "chrome" {
		t.Errorf("ClientFingerprint = %q", node.ClientFingerprint)
	}
	if node.PublicKey != "TestPublicKey1234567890" {
		t.Errorf("PublicKey = %q", node.PublicKey)
	}
	if node.ShortID != "29845e28" {
		t.Errorf("ShortID = %q, want 原值 29845e28", node.ShortID)
	}
	if node.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q", node.Flow)
	}
	if node.Network != "tcp" {
		t.Errorf("Network = %q", node.Network)
	}
}

// TestVLESSPrefixFallbacks 验证 sni→peer、insecure→allowInsecure 回退与
// 无 fragment 时缺省名 host:port。
func TestVLESSPrefixFallbacks(t *testing.T) {
	node, err := ParseLink("vless://uuid-1@5.6.7.8:8443?security=tls&peer=peer.example.com&allowInsecure=1")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !node.TLSSecure {
		t.Errorf("security=tls 应置 TLSSecure=true")
	}
	if node.SNI != "peer.example.com" {
		t.Errorf("SNI 应回退读 peer 参数, got %q", node.SNI)
	}
	if !node.SkipCertVerify {
		t.Errorf("allowInsecure=1 应置 SkipCertVerify=true")
	}
	if node.Name != "5.6.7.8:8443" {
		t.Errorf("缺省名称应为 host:port, got %q", node.Name)
	}
	if node.Network != "tcp" {
		t.Errorf("缺省传输类型应为 tcp, got %q", node.Network)
	}
}

// TestVLESSWSAndGRPC 覆盖 ws / grpc 两种传输的参数读取。
func TestVLESSWSAndGRPC(t *testing.T) {
	ws, err := ParseLink("vless://u-1@a.b.c:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D1&sni=cdn.example.com#ws节点")
	if err != nil {
		t.Fatalf("ws 解析失败: %v", err)
	}
	if ws.Network != "ws" || ws.WSPath != "/ws?ed=1" || ws.WSHeaders["Host"] != "cdn.example.com" {
		t.Errorf("ws 传输字段错误: %+v", ws)
	}

	grpc, err := ParseLink("vless://u-2@d.e.f:443?security=reality&type=grpc&serviceName=grpc-svc&mode=multi#grpc节点")
	if err != nil {
		t.Fatalf("grpc 解析失败: %v", err)
	}
	if grpc.Network != "grpc" || grpc.GRPCServiceName != "grpc-svc" || grpc.GRPCMode != "multi" {
		t.Errorf("grpc 传输字段错误: %+v", grpc)
	}

	// mode 缺省 gun（对齐 C++ vlessConstruct）
	grpc2, err := ParseLink("vless://u-3@d.e.f:443?type=grpc&serviceName=svc")
	if err != nil {
		t.Fatalf("grpc 解析失败: %v", err)
	}
	if grpc2.GRPCMode != "gun" {
		t.Errorf("grpc mode 缺省应为 gun, got %q", grpc2.GRPCMode)
	}
}

// TestVLESSErrors 反例：缺 UUID、缺 @、非法端口、未知传输类型。
func TestVLESSErrors(t *testing.T) {
	bad := []string{
		"vless://1.2.3.4:443",                 // 缺 userinfo
		"vless://uuid-1@1.2.3.4",              // 缺端口
		"vless://uuid-1@1.2.3.4:abc",          // 端口非数字
		"vless://uuid-1@1.2.3.4:443?type=kcp", // 未知传输类型
		"vless://uuid-1@1.2.3.4:0",            // 端口 0
	}
	for _, link := range bad {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("链接 %q 应解析失败", link)
		}
	}
}

// TestVLESSALPNAndIPv6 alpn 逗号拆分与 IPv6 字面量主机。
func TestVLESSALPNAndIPv6(t *testing.T) {
	node, err := ParseLink("vless://u-1@[2001:db8::1]:443?security=tls&alpn=h2,http/1.1&type=tcp")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Server != "2001:db8::1" {
		t.Errorf("IPv6 主机应去方括号, got %q", node.Server)
	}
	if len(node.ALPN) != 2 || node.ALPN[0] != "h2" || node.ALPN[1] != "http/1.1" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", node.ALPN)
	}
}
