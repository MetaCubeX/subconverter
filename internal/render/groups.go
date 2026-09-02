package render

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"subconv/internal/model"
	"subconv/internal/rule"
)

// renderGroups 由 ACL 策略组定义生成 proxy-groups 的 yaml 节点列表。
// acl 为空时返回 nil（不输出该段）。
//
// 内容项解析顺序（对真实 ACL4SSR 文件与简化语法均兼容）：
//  1. []X 前缀：引用组 X（X 必须是已定义组名或 DIRECT/REJECT，否则 fail-fast）
//  2. 裸 DIRECT / REJECT：内置出站
//  3. 与已定义组名精确相等：组引用（简化语法的"其他组名"项）
//  4. 其余：按节点名正则匹配（非锚定，对齐 C++ regFind 语义），
//     选中的节点按订阅顺序展开填入；正则编译失败退化为子串匹配
func renderGroups(nodes []model.Proxy, acl *rule.ACLConfig) ([]yaml.Node, error) {
	if acl == nil || len(acl.Groups) == 0 {
		return nil, nil
	}

	// 组名索引（同名组后定义覆盖先定义，对齐 C++ 的 replace 逻辑）
	groupNames := make(map[string]bool, len(acl.Groups))
	for _, g := range acl.Groups {
		groupNames[g.Name] = true
	}

	var groups []yaml.Node
	for _, g := range acl.Groups {
		proxies, err := expandGroupItems(g, nodes, groupNames)
		if err != nil {
			return nil, fmt.Errorf("策略组 %q: %w", g.Name, err)
		}

		m := mapNode()
		setStr(m, "name", g.Name)
		setField(m, "type", strNode(string(g.Type)))
		switch g.Type {
		case rule.GroupURLTest, rule.GroupFallback, rule.GroupLoadBalance:
			setStr(m, "url", g.URL)
			setInt(m, "interval", g.Interval)
			setInt(m, "tolerance", g.Tolerance)
			if g.Type == rule.GroupLoadBalance {
				strategy := g.Strategy
				if strategy == "" {
					strategy = "consistent-hashing"
				}
				setStr(m, "strategy", strategy)
			}
		}

		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for _, name := range proxies {
			seq.Content = append(seq.Content, strNode(name))
		}
		setField(m, "proxies", seq)
		groups = append(groups, *m)
	}
	return groups, nil
}

// expandGroupItems 展开单个策略组的内容项为出站名列表（去重、保持顺序）。
func expandGroupItems(g rule.GroupConfig, nodes []model.Proxy, groupNames map[string]bool) ([]string, error) {
	var out []string
	seen := make(map[string]bool)

	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}

	for _, item := range g.Items {
		switch {
		case strings.HasPrefix(item, "[]"):
			ref := strings.TrimPrefix(item, "[]")
			if ref != "DIRECT" && ref != "REJECT" && !groupNames[ref] {
				return nil, fmt.Errorf("引用的组 %q 不存在", ref)
			}
			add(ref)
		case item == "DIRECT", item == "REJECT":
			add(item)
		case item != g.Name && groupNames[item]:
			// 简化语法：裸项与组名精确相等 → 组引用；
			// 与自身组名相等时视为正则（引用自身无意义）
			add(item)
		default:
			// 正则项：按节点名非锚定匹配（C++ groupGenerate 语义），编译失败退化子串
			for i := range nodes {
				if matchNodeName(nodes[i].Name, item) {
					add(nodes[i].Name)
				}
			}
		}
	}

	// 展开后为空（如正则无命中）兜底 DIRECT，对齐 C++ filtered_nodelist 行为
	if len(out) == 0 {
		out = []string{"DIRECT"}
	}
	return out, nil
}

// matchNodeName 判断节点名是否命中正则项：优先 RE2（非锚定 search），
// 编译失败（如含 RE2 不支持的 lookahead）退化为子串包含。
func matchNodeName(name, pattern string) bool {
	if pattern == "" {
		return false
	}
	if re, err := regexp.Compile(pattern); err == nil {
		return re.MatchString(name)
	}
	return strings.Contains(name, pattern)
}
