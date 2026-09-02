package fetch

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 测试用订阅与流量头样本。
var (
	plainSub    = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=PbKey123&sid=29845e28&type=tcp&flow=xtls-rprx-vision#%E9%A6%99%E6%B8%AF01\ntrojan://pw123@5.6.7.8:443?sni=a.example.com#%E6%97%A5%E6%9C%AC01"
	base64Sub   = base64.StdEncoding.EncodeToString([]byte(plainSub))
	subUserInfo = "upload=123; download=456; total=789; expire=1735689600"
)

// TestFetchSubscriptionBase64WithUserinfo 基础路径：拉取 base64 订阅正文原样返回、
// subscription-userinfo 头解析为 map、默认 UA 为 clash.meta。
func TestFetchSubscriptionBase64WithUserinfo(t *testing.T) {
	var gotUA atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA.Store(r.Header.Get("User-Agent"))
		w.Header().Set("subscription-userinfo", subUserInfo)
		_, _ = w.Write([]byte(base64Sub))
	}))
	defer srv.Close()

	content, userinfo, err := FetchSubscription(srv.URL, "")
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if content != base64Sub {
		t.Errorf("内容应原样返回（base64 解码由 parser 层负责）")
	}
	if ua, _ := gotUA.Load().(string); ua != "clash.meta" {
		t.Errorf("默认 UA = %q, want clash.meta", ua)
	}
	want := map[string]string{
		"upload": "123", "download": "456", "total": "789", "expire": "1735689600",
	}
	if !reflect.DeepEqual(userinfo, want) {
		t.Errorf("userinfo = %v, want %v", userinfo, want)
	}
}

// TestFetchSubscriptionCustomUA 自定义 UA 透传。
func TestFetchSubscriptionCustomUA(t *testing.T) {
	var gotUA atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA.Store(r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte(base64Sub))
	}))
	defer srv.Close()

	if _, _, err := FetchSubscription(srv.URL, "v2rayng/1.9.0"); err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if ua, _ := gotUA.Load().(string); ua != "v2rayng/1.9.0" {
		t.Errorf("自定义 UA = %q, want v2rayng/1.9.0", ua)
	}
}

// TestFetchSubscriptionNoUserinfoHeader 无 subscription-userinfo 头时 userinfo 为 nil。
func TestFetchSubscriptionNoUserinfoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(base64Sub))
	}))
	defer srv.Close()

	_, userinfo, err := FetchSubscription(srv.URL, "")
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if userinfo != nil {
		t.Errorf("无流量头时 userinfo 应为 nil, got %v", userinfo)
	}
}

// TestFetchSubscriptionGzip Content-Encoding: gzip 响应自动解压。
func TestFetchSubscriptionGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(base64Sub)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	content, _, err := FetchSubscription(srv.URL, "")
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if content != base64Sub {
		t.Errorf("gzip 响应应解压为原始 base64 订阅, got %q", truncate(content, 60))
	}
}

// TestFetchSubscriptionRetry 首次 500、重试成功：单次重试生效。
func TestFetchSubscriptionRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(base64Sub))
	}))
	defer srv.Close()

	content, _, err := FetchSubscription(srv.URL, "")
	if err != nil {
		t.Fatalf("重试后应成功: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("请求次数 = %d, want 2（首次失败 + 重试一次）", n)
	}
	if content != base64Sub {
		t.Errorf("重试成功后内容错误")
	}
}

// TestFetchSubscriptionNon200RetryExhausted 持续 500：重试耗尽后报错并带状态码。
func TestFetchSubscriptionNon200RetryExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, _, err := FetchSubscription(srv.URL, "")
	if err == nil {
		t.Fatal("持续 403 应报错")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("错误信息应包含状态码 403, got %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("请求次数 = %d, want 2（重试一次后放弃）", n)
	}
}

// TestFetchSubscriptionTimeout 超时路径：注入短超时 client，服务端手动 sleep 模拟慢响应，
// 两次尝试（含重试）均超时后报错。
func TestFetchSubscriptionTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(base64Sub))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 50 * time.Millisecond}
	_, _, err := fetchWithClient(client, srv.URL, "")
	if err == nil {
		t.Fatal("超时应报错")
	}
	if !strings.Contains(err.Error(), "拉取") {
		t.Errorf("错误信息应指明拉取失败, got %v", err)
	}
}

// TestParseSubscriptionUserinfo 头解析单测：常规/乱序/含未知段/空。
func TestParseSubscriptionUserinfo(t *testing.T) {
	cases := []struct {
		name, header string
		want         map[string]string
	}{
		{
			name:   "常规",
			header: "upload=123; download=456; total=789",
			want:   map[string]string{"upload": "123", "download": "456", "total": "789"},
		},
		{
			name:   "含空格与未知段",
			header: "upload=1 ; download=2; total=3; bad-segment",
			want:   map[string]string{"upload": "1", "download": "2", "total": "3"},
		},
		{name: "空", header: "", want: nil},
		{name: "无等号", header: "garbage", want: nil},
	}
	for _, c := range cases {
		if got := parseSubscriptionUserinfo(c.header); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: parseSubscriptionUserinfo(%q) = %v, want %v", c.name, c.header, got, c.want)
		}
	}
}

// truncate 测试失败输出截断。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
