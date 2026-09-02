// Package filter 实现节点过滤：include/exclude 正则（RE2 语法）。
// 注意与 C++（PCRE2）的差异：RE2 不支持 lookahead/lookbehind，
// 机场侧正则需按子串/前缀风格书写。
package filter

import (
	"regexp"

	"subconv/internal/model"
)

// FilterNodes 按节点 Name 过滤：
//   - include 非空：仅保留匹配的节点
//   - exclude 非空：剔除匹配的节点
//
// 正则采用 RE2；编译失败或空串时忽略对应条件（不做过滤）。
// include 与 exclude 可同时生效，先过 include 再过 exclude。
func FilterNodes(nodes []model.Proxy, include, exclude string) []model.Proxy {
	inc := compileOrNull(include)
	exc := compileOrNull(exclude)

	out := make([]model.Proxy, 0, len(nodes))
	for _, n := range nodes {
		if inc != nil && !inc.MatchString(n.Name) {
			continue
		}
		if exc != nil && exc.MatchString(n.Name) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// compileOrNull 编译正则；空串或非法正则返回 nil（表示该条件忽略）。
func compileOrNull(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if re, err := regexp.Compile(pattern); err == nil {
		return re
	}
	return nil
}
