// Package server 提供 HTTP 服务：路由注册与请求处理。
// Phase 3+4 后 /sub 支持完整链路：
// 节点链接/订阅 URL 混合输入（| 分隔多段，http(s) 段经 FetchSubscription 拉取）
// → 解析 → include/exclude 过滤 → ACL 外配置 → clash/loon 双目标渲染。
// 纯 net/http 不引框架。
package server

import (
	"fmt"
	"net/http"
	"strings"

	"subconv/internal/fetch"
	"subconv/internal/filter"
	"subconv/internal/model"
	"subconv/internal/parser"
	"subconv/internal/render"
	"subconv/internal/rule"
)

// Version 当前版本号。
const Version = "v0.1.0"

// defaultACLConfig /sub 未传 config 参数（非必填）时的默认外配置：直接指向
// ACL4SSR 仓库 master 分支的最新 Online_Full.ini，规则配置随上游自动更新。
// 需要特定配置时通过 config 参数显式指定。
const defaultACLConfig = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Full.ini"

// NewHandler 构建根路由。
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/version", handleVersion)
	mux.HandleFunc("/sub", handleSub)
	return mux
}

// handleVersion 返回版本信息。
func handleVersion(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "subconverter-go %s backend\n", Version)
}

// subParams /sub 请求参数。
type subParams struct {
	Target   string // 目标格式：clash / loon
	URL      string // 订阅地址（或 | 分隔的节点链接列表），可用 | 分隔多个，支持混合
	Config   string // 规则/策略组外配置（非必填，仅支持完整 http(s) URL；默认 ACL4SSR_Online_Full.ini）
	Filename string // 响应 Content-Disposition 文件名
	UA       string // 拉取订阅时使用的 User-Agent
	Include  string // 保留节点的正则
	Exclude  string // 剔除节点的正则
}

// handleSub 订阅转换入口。
//
// 行为约束：
//   - target 支持 clash / loon，其他值返回 400
//   - url 支持 | 分隔多段，节点链接与 http(s) 订阅地址可混合；
//     任一订阅段拉取/解析失败即整体 400（对齐 C++ addNodes 失败即报错的严格行为）
//   - 订阅段的 subscription-userinfo 以 Subscription-UserInfo 头回传
//     （对齐 C++ appendUserinfo）
//   - config 仅支持完整 http(s) URL（拉取失败即 400）；不传时用默认远程外配置
func handleSub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	params := subParams{
		Target:   q.Get("target"),
		URL:      q.Get("url"),
		Config:   q.Get("config"),
		Filename: q.Get("filename"),
		UA:       q.Get("ua"),
		Include:  q.Get("include"),
		Exclude:  q.Get("exclude"),
	}

	// 目标格式校验
	switch params.Target {
	case "clash", "loon":
	default:
		http.Error(w, "unsupported target: "+params.Target+"（仅支持 clash/loon）", http.StatusBadRequest)
		return
	}

	if params.URL == "" {
		http.Error(w, "missing url parameter", http.StatusBadRequest)
		return
	}

	// 节点收集：| 分隔多段，节点链接与 http(s) 订阅地址混合
	nodes, userinfo, err := collectNodes(params.URL, params.UA)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// include/exclude 过滤
	if params.Include != "" || params.Exclude != "" {
		nodes = filter.FilterNodes(nodes, params.Include, params.Exclude)
	}
	if len(nodes) == 0 {
		http.Error(w, "no node left after include/exclude filter", http.StatusBadRequest)
		return
	}

	// 外部配置（ACL ini）：远程拉取，无本地兜底，失败即 400
	configName := params.Config
	if configName == "" {
		configName = defaultACLConfig
	}
	aclContent, err := loadExternalConfig(configName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	acl, err := rule.ParseINI(aclContent)
	if err != nil {
		http.Error(w, fmt.Sprintf("解析外配置 %s 失败: %v", configName, err), http.StatusBadRequest)
		return
	}

	// 渲染
	output, err := render.Convert(params.Target, nodes, &render.Config{ACL: acl})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(userinfo) > 0 {
		w.Header().Set("Subscription-UserInfo", formatUserinfo(userinfo))
	}
	contentType := "text/yaml; charset=utf-8"
	if params.Target == "loon" {
		contentType = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	if params.Filename != "" {
		w.Header().Set("Content-Disposition", "attachment; filename="+params.Filename)
	}
	_, _ = w.Write([]byte(output))
}

// collectNodes 收集全部节点：url 参数按 | 分隔多段，每段可为节点链接或
// http(s) 订阅地址，后者经 fetch.FetchSubscription 拉取后由 ParseSubscription 解析。
// 任一 http 段拉取或解析失败即整体报错（对齐 C++ 的严格行为）；
// 返回首个携带 subscription-userinfo 的订阅的流量信息。
func collectNodes(urlParam, ua string) ([]model.Proxy, map[string]string, error) {
	var nodes []model.Proxy
	var userinfo map[string]string
	for _, part := range strings.Split(urlParam, "|") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if isHTTPURL(part) {
			content, info, err := fetch.FetchSubscription(part, ua)
			if err != nil {
				return nil, nil, err
			}
			if userinfo == nil && len(info) > 0 {
				userinfo = info
			}
			subNodes, err := parser.ParseSubscription(content)
			if err != nil {
				return nil, nil, fmt.Errorf("订阅 %s 解析失败: %w", part, err)
			}
			nodes = append(nodes, subNodes...)
			continue
		}
		node, err := parser.ParseLink(part)
		if err != nil {
			return nil, nil, fmt.Errorf("节点链接解析失败: %w", err)
		}
		nodes = append(nodes, *node)
	}
	if len(nodes) == 0 {
		return nil, nil, fmt.Errorf("url 参数不含任何节点链接或订阅地址")
	}
	return nodes, userinfo, nil
}

// isHTTPURL 判断段是否为 http(s) 订阅地址。
func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// userinfoOrder Subscription-UserInfo 响应头的字段输出顺序。
var userinfoOrder = []string{"upload", "download", "total", "expire"}

// formatUserinfo 把 userinfo map 还原为响应头格式：upload=1; download=2; total=3。
func formatUserinfo(userinfo map[string]string) string {
	var parts []string
	for _, k := range userinfoOrder {
		if v, ok := userinfo[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// loadExternalConfig 加载外配置内容：config 参数只支持完整 http(s) URL
// （如 https://raw.githubusercontent.com/.../ACL4SSR_Online_Mini.ini），
// 不支持裸名字。下载失败（网络不可达 / 非 200）即返回错误，由调用方转为 400。
func loadExternalConfig(configURL string) (string, error) {
	if !isHTTPURL(configURL) {
		return "", fmt.Errorf("外配置 %q 非法：仅支持 http(s) URL", configURL)
	}
	content, err := render.FetchRemote(configURL)
	if err != nil {
		return "", fmt.Errorf("外配置拉取失败: %w", err)
	}
	return content, nil
}
