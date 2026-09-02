package parser

import "testing"

// TestParseLinkDispatch registry 分发：未知协议 / 缺协议前缀应报错。
func TestParseLinkDispatch(t *testing.T) {
	for _, link := range []string{
		"unknown://xxx",
		"没有前缀的链接",
		"://empty-scheme",
	} {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("链接 %q 应返回 error", link)
		}
	}
	// 前后空白应被容忍
	if _, err := ParseLink("  vless://u@1.2.3.4:443?type=tcp  "); err != nil {
		t.Errorf("带空白的合法链接应解析成功: %v", err)
	}
}

// TestBase64DecodeAny 覆盖标准 / URL-safe / 缺 padding / 内嵌空白 / 非法输入。
func TestBase64DecodeAny(t *testing.T) {
	// 标准 + padding
	if got, err := base64DecodeAny("aGVsbG8="); err != nil || string(got) != "hello" {
		t.Errorf("标准 base64 解码错误: %q, %v", got, err)
	}
	// URL-safe 无 padding
	if got, err := base64DecodeAny("aGVsbG8"); err != nil || string(got) != "hello" {
		t.Errorf("无 padding base64 解码错误: %q, %v", got, err)
	}
	// URL-safe 字母表（- 与 _）
	if got, err := base64DecodeAny("_-8="); err != nil || len(got) != 2 {
		t.Errorf("URL-safe 字母表解码错误: %q, %v", got, err)
	}
	// 内嵌换行（base64 订阅常见的 76 列折行）
	if got, err := base64DecodeAny("aGVs\nbG8="); err != nil || string(got) != "hello" {
		t.Errorf("含换行的 base64 解码错误: %q, %v", got, err)
	}
	// 非法输入
	for _, bad := range []string{"", "!!!", "a", "abcde"} {
		if _, err := base64DecodeAny(bad); err == nil {
			t.Errorf("非法 base64 %q 应返回 error", bad)
		}
	}
}

// TestURLDecodeLenient 宽松解码：正常转义、+ 转空格、非法转义原样返回。
func TestURLDecodeLenient(t *testing.T) {
	if got := urlDecode("%E8%8A%82%E7%82%B9"); got != "节点" {
		t.Errorf("中文转义解码错误: %q", got)
	}
	if got := urlDecode("a+b"); got != "a b" {
		t.Errorf("+ 应转空格: %q", got)
	}
	if got := urlDecode("100%"); got != "100%" {
		t.Errorf("非法转义应原样返回: %q", got)
	}
	if got := urlDecode("plain"); got != "plain" {
		t.Errorf("无转义内容应原样返回: %q", got)
	}
}

// TestParseQuery 查询参数解析：值解码、重复键取首个、空值容忍。
func TestParseQuery(t *testing.T) {
	q := parseQuery("a=1&b=%E4%B8%AD&c&d=4&d=5")
	if q["a"] != "1" || q["b"] != "中" || q["c"] != "" || q["d"] != "4" {
		t.Errorf("查询参数解析错误: %v", q)
	}
	if len(parseQuery("")) != 0 {
		t.Errorf("空查询串应返回空表")
	}
}

// TestSplitHostPort 主机端口拆分：常规、IPv6、反例。
func TestSplitHostPort(t *testing.T) {
	if h, p, err := splitHostPort("example.com:443"); err != nil || h != "example.com" || p != 443 {
		t.Errorf("常规拆分错误: %q %d %v", h, p, err)
	}
	if h, p, err := splitHostPort("[2001:db8::1]:8443"); err != nil || h != "2001:db8::1" || p != 8443 {
		t.Errorf("IPv6 拆分错误: %q %d %v", h, p, err)
	}
	for _, bad := range []string{"no-port", "host:abc", "host:0", "host:70000", ":443"} {
		if _, _, err := splitHostPort(bad); err == nil {
			t.Errorf("%q 应返回 error", bad)
		}
	}
}
