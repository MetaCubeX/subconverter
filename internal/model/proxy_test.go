package model

import "testing"

// TestProxyTypeString 验证协议类型可读名称与 Clash/mihomo type 字段一致。
func TestProxyTypeString(t *testing.T) {
	cases := map[ProxyType]string{
		TypeVLESS:     "vless",
		TypeVMess:     "vmess",
		TypeSS:        "ss",
		TypeTrojan:    "trojan",
		TypeHysteria2: "hysteria2",
		TypeAnyTLS:    "anytls",
		TypeUnknown:   "unknown",
	}
	for typ, want := range cases {
		if got := typ.String(); got != want {
			t.Errorf("ProxyType(%d).String() = %q, want %q", int(typ), got, want)
		}
	}
}
