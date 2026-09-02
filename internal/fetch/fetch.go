// Package fetch 实现订阅拉取（Phase 3）：HTTP GET、自定义 User-Agent、
// 超时与失败单次重试、subscription-userinfo 响应头提取、gzip 自动解压。
// 行为对齐 C++ 版 webget/nodemanip 的订阅获取路径。
package fetch

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// 拉取默认参数。
const (
	// defaultUA 默认 User-Agent：clash.meta（机场侧普遍按该 UA 返回 Clash 订阅）
	defaultUA = "clash.meta"
	// fetchTimeout 单次请求超时
	fetchTimeout = 10 * time.Second
	// maxRetries 失败后的重试次数（总尝试 = 1 + maxRetries）
	maxRetries = 1
	// maxBodySize 响应体上限 32MB（与规则集下载上限一致）
	maxBodySize = 32 << 20
)

// fetchClient 订阅拉取专用 HTTP client（固定 10s 超时）。
// 测试通过 fetchWithClient 注入自定义超时的 client。
var fetchClient = &http.Client{Timeout: fetchTimeout}

// FetchSubscription 拉取订阅内容并解析 subscription-userinfo 响应头。
//
//   - ua 为空时默认 "clash.meta"
//   - 单次请求超时 10s；失败（网络错误或非 200 状态码）自动重试一次
//   - subscription-userinfo 头（如 "upload=123; download=456; total=789"）
//     解析为 map 返回；无该头时返回 nil
//   - 响应 Content-Encoding 为 gzip 时自动解压
func FetchSubscription(url, ua string) (content string, userinfo map[string]string, err error) {
	return fetchWithClient(fetchClient, url, ua)
}

// fetchWithClient 使用指定 client 拉取（测试注入自定义超时用）。
func fetchWithClient(client *http.Client, url, ua string) (string, map[string]string, error) {
	if ua == "" {
		ua = defaultUA
	}
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		content, userinfo, err := doFetch(client, url, ua)
		if err == nil {
			return content, userinfo, nil
		}
		lastErr = err
	}
	return "", nil, lastErr
}

// doFetch 单次拉取：请求构造 → 状态码校验 → 限长读取 → gzip 解压 → 头解析。
func doFetch(client *http.Client, url, ua string) (string, map[string]string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", nil, fmt.Errorf("构造请求 %s 失败: %w", url, err)
	}
	req.Header.Set("User-Agent", ua)
	// 显式声明接受 gzip：禁用 net/http 的透明解压，
	// 使 Content-Encoding 保留在响应头上，由本包统一解压
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("拉取 %s 失败: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("拉取 %s 返回状态码 %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return "", nil, fmt.Errorf("读取 %s 响应失败: %w", url, err)
	}
	content, err := gunzipIfNeeded(body, resp.Header.Get("Content-Encoding"))
	if err != nil {
		return "", nil, fmt.Errorf("解压 %s 响应失败: %w", url, err)
	}
	return content, parseSubscriptionUserinfo(resp.Header.Get("subscription-userinfo")), nil
}

// gunzipIfNeeded 按响应头 Content-Encoding 解压 gzip 响应体；非 gzip 原样返回。
func gunzipIfNeeded(body []byte, contentEncoding string) (string, error) {
	if !strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip") {
		return string(body), nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer zr.Close()
	decoded, err := io.ReadAll(zr)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// parseSubscriptionUserinfo 解析 subscription-userinfo 头：
// 分号分隔的 k=v 对（如 "upload=123; download=456; total=789"）。
// 头缺失、为空或不含任何合法 k=v 对时返回 nil。
func parseSubscriptionUserinfo(header string) map[string]string {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	userinfo := make(map[string]string)
	for _, kv := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		userinfo[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(userinfo) == 0 {
		return nil
	}
	return userinfo
}
