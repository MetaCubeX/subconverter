package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"subconv/internal/parser"
)

// setupACL 注入外配置动态拉取环境：httptest 服务器 serve 测试样本
// testdata/acl_mini.ini，返回该 ini 的完整 URL（config 参数只支持完整 URL）。
func setupACL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile("../../testdata/acl_mini.ini")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/acl_mini.ini"
}

// nodeLink1/2 测试用节点链接（vless REALITY + trojan）。
const (
	nodeLink1 = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=PbKey123&sid=29845e28&type=tcp&flow=xtls-rprx-vision#%E9%A6%99%E6%B8%AF01"
	nodeLink2 = "trojan://pw123@5.6.7.8:443?sni=a.example.com#%E6%97%A5%E6%9C%AC01"
)

// TestVersionEndpoint /version 返回版本行。
func TestVersionEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	want := "subconverter-go " + Version + " backend\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestSubClashFullChain /sub clash 全链路：
// 节点链接解析 → 离线 ACL 配置（避免测试依赖网络）→ 策略组/规则渲染。
func TestSubClashFullChain(t *testing.T) {
	acl := setupACL(t)
	q := "target=clash&url=" + url.QueryEscape(nodeLink1+"|"+nodeLink2) +
		"&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/yaml; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}

	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
		Groups  []map[string]any `yaml:"proxy-groups"`
		Rules   []string         `yaml:"rules"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("响应不是合法 YAML: %v\n%s", err, rec.Body.String())
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("proxies 数 = %d, want 2", len(doc.Proxies))
	}
	if len(doc.Groups) != 5 {
		t.Fatalf("proxy-groups 数 = %d, want 5（acl_mini.ini）", len(doc.Groups))
	}
	// GEOIP 内联规则始终存在（example.com ruleset 网络失败跳过）
	if len(doc.Rules) < 2 {
		t.Fatalf("rules 数 = %d, want ≥ 2（GEOIP + MATCH）", len(doc.Rules))
	}
	if last := doc.Rules[len(doc.Rules)-1]; last != "MATCH,🐟 漏网之鱼" {
		t.Errorf("MATCH 兜底 = %q", last)
	}
	// short-id 双引号强制字符串（29845e28 不被解析为浮点数）
	ro := doc.Proxies[0]["reality-opts"].(map[string]any)
	if ro["short-id"] != "29845e28" {
		t.Errorf("short-id = %v (%T), want string 29845e28", ro["short-id"], ro["short-id"])
	}
}

// TestSubFilename filename 参数 → Content-Disposition 附件头。
func TestSubFilename(t *testing.T) {
	acl := setupACL(t)
	q := "target=clash&url=" + url.QueryEscape(nodeLink1) +
		"&config=" + url.QueryEscape(acl) + "&filename=my-config.yaml"
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "attachment; filename=my-config.yaml" {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

// TestSubIncludeExclude include/exclude 过滤。
func TestSubIncludeExclude(t *testing.T) {
	acl := setupACL(t)
	q := "target=clash&url=" + url.QueryEscape(nodeLink1+"|"+nodeLink2) +
		"&config=" + url.QueryEscape(acl) + "&include=" + url.QueryEscape("香港")
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	nodes, err := parser.ParseSubscription(nodeLink1 + "\n" + nodeLink2)
	if err != nil {
		t.Fatal(err)
	}
	// include=香港 应只保留 香港01（排除 日本01）
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("响应不是合法 YAML: %v", err)
	}
	if len(doc.Proxies) != 1 || doc.Proxies[0]["name"] != nodes[0].Name {
		t.Errorf("include 过滤结果错误: %+v", doc.Proxies)
	}

	// exclude 全部过滤后 → 400
	q = "target=clash&url=" + url.QueryEscape(nodeLink1) +
		"&config=" + url.QueryEscape(acl) + "&exclude=" + url.QueryEscape("香港|日本")
	req = httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec = httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("全部节点被过滤应 400, got %d", rec.Code)
	}
}

// TestSubHTTPSubscriptionUnavailable http(s) 订阅地址拉取失败（500）→ 400，
// 对齐 C++ 严格行为：任一订阅段失败即整体报错。
func TestSubHTTPSubscriptionUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/sub?target=clash&url="+url.QueryEscape(srv.URL), nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "500") {
		t.Errorf("错误信息应包含状态码 500, got %q", body)
	}
}

// TestSubLoonTarget target=loon 全链路：输出 Loon conf 结构与节点行。
func TestSubLoonTarget(t *testing.T) {
	acl := setupACL(t)
	q := "target=loon&url=" + url.QueryEscape(nodeLink1+"|"+nodeLink2) +
		"&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	for _, section := range []string{"[General]", "[Proxy]", "[Proxy Group]", "[Rule]", "[Remote Rule]"} {
		if !strings.Contains(body, section) {
			t.Errorf("Loon 输出缺少段头 %s:\n%s", section, body)
		}
	}
	// vless REALITY 节点行（shortId 原值）与 trojan 节点行
	if !strings.Contains(body, `香港01 = vless,1.2.3.4,443,"11111111-2222-3333-4444-555555555555",tls=true,sni=www.microsoft.com,flow=xtls-rprx-vision,transport=tcp,publicKey=PbKey123,shortId=29845e28`) {
		t.Errorf("vless REALITY 节点行错误:\n%s", body)
	}
	if !strings.Contains(body, `日本01 = trojan,5.6.7.8,443,"pw123",tls-name=a.example.com`) {
		t.Errorf("trojan 节点行错误:\n%s", body)
	}
	// Loon 规则用 FINAL 而非 MATCH
	if !strings.Contains(body, "\nFINAL,🐟 漏网之鱼\n") {
		t.Errorf("应包含 FINAL 兜底规则:\n%s", body)
	}
	if strings.Contains(body, "MATCH,") {
		t.Errorf("Loon 规则不应出现 MATCH:\n%s", body)
	}
}

// TestSubMultiURLMerge 多个订阅 URL 合并：两个 httptest 订阅各返回一个节点，
// 合并后 2 个节点；subscription-userinfo 以响应头回传。
func TestSubMultiURLMerge(t *testing.T) {
	acl := setupACL(t)
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=123; download=456; total=789")
		_, _ = w.Write([]byte(nodeLink1 + "\n"))
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodeLink2 + "\n"))
	}))
	defer srv2.Close()

	q := "target=clash&url=" + url.QueryEscape(srv1.URL+"|"+srv2.URL) + "&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if su := rec.Header().Get("Subscription-UserInfo"); su != "upload=123; download=456; total=789" {
		t.Errorf("Subscription-UserInfo = %q", su)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("响应不是合法 YAML: %v", err)
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("合并后节点数 = %d, want 2", len(doc.Proxies))
	}
}

// TestSubMultiURLFailure 多 URL 任一失败 → 400。
func TestSubMultiURLFailure(t *testing.T) {
	acl := setupACL(t)
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodeLink1 + "\n"))
	}))
	defer srvOK.Close()
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srvBad.Close()

	q := "target=clash&url=" + url.QueryEscape(srvOK.URL+"|"+srvBad.URL) + "&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("任一订阅失败应 400, got %d, body: %s", rec.Code, rec.Body.String())
	}
}

// TestSubURLMixed 节点链接 + 订阅 URL 混合（| 分隔）。
func TestSubURLMixed(t *testing.T) {
	acl := setupACL(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodeLink2 + "\n"))
	}))
	defer srv.Close()

	q := "target=clash&url=" + url.QueryEscape(nodeLink1+"|"+srv.URL) + "&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("响应不是合法 YAML: %v", err)
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("混合输入节点数 = %d, want 2", len(doc.Proxies))
	}
}

// TestSubBadTarget 非法 target 返回 400 且错误信息明确。
func TestSubBadTarget(t *testing.T) {
	for _, target := range []string{"surge", "quantumult", "ss", ""} {
		req := httptest.NewRequest(http.MethodGet, "/sub?target="+target+"&url=x", nil)
		rec := httptest.NewRecorder()
		NewHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("target=%q: status = %d, want 400", target, rec.Code)
			continue
		}
		if body := rec.Body.String(); !strings.Contains(body, "unsupported target") {
			t.Errorf("target=%q: body = %q, 应含 unsupported target", target, body)
		}
	}
}

// TestSubMissingParams 缺 url / url 全空段 / config 非法（裸名字、不存在）。
func TestSubMissingParams(t *testing.T) {
	setupACL(t)
	cases := []struct {
		name, query string
	}{
		{"缺url", "target=clash"},
		{"空url段", "target=clash&url=%20%7C%20"},
		{"config裸名字拒绝", "target=clash&url=" + url.QueryEscape(nodeLink1) + "&config=NoSuch.ini"},
		{"config不存在", "target=clash&url=" + url.QueryEscape(nodeLink1) + "&config=http%3A%2F%2F127.0.0.1%3A1%2Fno.ini"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/sub?"+c.query, nil)
		rec := httptest.NewRecorder()
		NewHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400, body: %s", c.name, rec.Code, rec.Body.String())
		}
	}
}

// TestSubMethodNotAllowed 非 GET 请求返回 405。
func TestSubMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/sub?target=clash", nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
