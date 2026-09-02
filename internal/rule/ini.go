// Package rule 解析 ACL4SSR 风格的外部配置（ini），
// 产出策略组（custom_proxy_group）与规则集（ruleset）两类定义，
// 供渲染层（internal/render）生成 proxy-groups 与 rules 段。
//
// 方言说明（对齐 C++ 版 INIBinding::from<...>::from_ini）：
//   - 文件只有一个 [custom] 段；键前缀 ruleset / custom_proxy_group 为本包关心的语法，
//     其余已知键（enable_rule_generator / overwrite_original_rules / clash_rule_base）忽略
//   - custom_proxy_group 行以反引号分隔：name`type`item1`item2...
//     url-test / fallback / load-balance 尾部额外携带 `url`times`（load-balance 可再附 strategy）
//     item 形如 []组名 / []DIRECT / []REJECT 或匹配节点名的正则
//   - ruleset 行以逗号分隔：group,path 或 group,path,interval；
//     path 为 base 目录相对路径、https:// 远程地址，或 [] 开头的内联规则（如 []GEOIP,CN）
//   - 不认识的段 / 键 / 组类型一律 fail-fast 返回 error
package rule

import (
	"fmt"
	"strconv"
	"strings"
)

// GroupType 策略组类型。
type GroupType string

// 支持的四种策略组类型（本期范围）。
const (
	GroupSelect      GroupType = "select"
	GroupURLTest     GroupType = "url-test"
	GroupFallback    GroupType = "fallback"
	GroupLoadBalance GroupType = "load-balance"
)

// 需要携带 url/interval 尾参数的组类型。
func (t GroupType) needsURL() bool {
	return t == GroupURLTest || t == GroupFallback || t == GroupLoadBalance
}

// GroupConfig 单个策略组定义（custom_proxy_group 一行的解析结果）。
type GroupConfig struct {
	Name      string    // 组名（可含中文/emoji）
	Type      GroupType // select / url-test / fallback / load-balance
	Items     []string  // 原始内容项：[]组名 引用，或匹配节点名的正则
	URL       string    // 测速 URL（url-test/fallback/load-balance）
	Interval  int       // 测速间隔秒数
	Tolerance int       // 容差毫秒（仅 url-test 有意义）
	Strategy  string    // load-balance 策略：consistent-hashing / round-robin
}

// RulesetConfig 单个规则集定义（ruleset 一行的解析结果）。
type RulesetConfig struct {
	Group  string // 命中的策略组名；空串表示未指定（渲染时用调用方默认策略）
	Path   string // 本地（base 目录相对）或 https:// 远程路径；内联规则时为空
	Inline string // [] 内联规则体，如 "GEOIP,CN" / "FINAL"；非内联时为空
}

// ACLConfig 一份外配置的完整解析结果。
type ACLConfig struct {
	Groups         []GroupConfig
	Rulesets       []RulesetConfig
	OverwriteRules bool   // overwrite_original_rules（本期总是覆盖，仅保留语义位）
	EnableRuleGen  bool   // enable_rule_generator
	ClashRuleBase  string // clash_rule_base（本期忽略内容，仅记录存在）
}

// knownIgnoreKeys [custom] 段内识别但本期不处理的键。
var knownIgnoreKeys = map[string]bool{
	"enable_rule_generator":    true,
	"overwrite_original_rules": true,
	"clash_rule_base":          true,
}

// ParseINI 解析 ACL4SSR 风格外配置全文。
// 遇到不认识的段、键或非法组定义时返回 error（fail-fast）。
func ParseINI(content string) (*ACLConfig, error) {
	cfg := &ACLConfig{}
	section := "" // 当前段名；空串等价于 [custom]（C++ 将孤立行归入 custom）

	for ln, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// 段头
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("ini 第 %d 行段头格式非法: %q", ln+1, line)
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section != "custom" {
				return nil, fmt.Errorf("ini 第 %d 行出现不认识的段 [%s]（本期仅支持 [custom]）", ln+1, section)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("ini 第 %d 行缺少 '=' 分隔: %q", ln+1, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if section != "" && section != "custom" {
			return nil, fmt.Errorf("ini 第 %d 行出现在不认识的段 [%s] 内", ln+1, section)
		}

		switch key {
		case "ruleset":
			rc, err := parseRulesetLine(value)
			if err != nil {
				return nil, fmt.Errorf("ini 第 %d 行 ruleset 定义非法: %w", ln+1, err)
			}
			cfg.Rulesets = append(cfg.Rulesets, *rc)
		case "custom_proxy_group":
			gc, err := parseGroupLine(value)
			if err != nil {
				return nil, fmt.Errorf("ini 第 %d 行 custom_proxy_group 定义非法: %w", ln+1, err)
			}
			cfg.Groups = append(cfg.Groups, *gc)
		case "enable_rule_generator":
			cfg.EnableRuleGen = parseBool(value)
		case "overwrite_original_rules":
			cfg.OverwriteRules = parseBool(value)
		case "clash_rule_base":
			cfg.ClashRuleBase = value
		default:
			return nil, fmt.Errorf("ini 第 %d 行出现不认识的键 %q", ln+1, key)
		}
	}
	return cfg, nil
}

// parseRulesetLine 解析 ruleset 行的值部分：group,path[,interval]。
// path 以 [] 开头时为内联规则；省略 group 前缀（无逗号）时 group 为空。
func parseRulesetLine(value string) (*RulesetConfig, error) {
	if value == "" {
		return nil, fmt.Errorf("值为空")
	}
	rc := &RulesetConfig{}
	rest := value
	if group, after, ok := strings.Cut(rest, ","); ok {
		rc.Group = strings.TrimSpace(group)
		rest = strings.TrimSpace(after)
	}
	if rest == "" {
		return nil, fmt.Errorf("规则集路径为空: %q", value)
	}
	if strings.HasPrefix(rest, "[]") {
		rc.Inline = strings.TrimPrefix(rest, "[]")
		if rc.Inline == "" {
			return nil, fmt.Errorf("内联规则为空: %q", value)
		}
		return rc, nil
	}
	// 尾部可选 interval：仅当最后一逗号后的部分为纯数字时视为间隔
	if path, tail, ok := strings.Cut(rest, ","); ok && isAllDigits(tail) {
		rc.Path = strings.TrimSpace(path)
		// interval 本期不做增量更新，仅校验合法性后丢弃
		if _, err := strconv.Atoi(tail); err != nil {
			return nil, fmt.Errorf("interval 非法: %q", tail)
		}
	} else {
		rc.Path = rest
	}
	if rc.Path == "" {
		return nil, fmt.Errorf("规则集路径为空: %q", value)
	}
	return rc, nil
}

// parseGroupLine 解析 custom_proxy_group 行的值部分。
// 支持两种方言：
//   - ACL4SSR 真实方言：反引号分隔 name`type`items...（判定依据：第二个反引号段为合法组类型，
//     或整个值不含逗号——此时只能按真实方言解析并让其报出类型错误）
//   - 简化方言：逗号分隔 name,type,items...，正则项用反引号包裹
func parseGroupLine(value string) (*GroupConfig, error) {
	if value == "" {
		return nil, fmt.Errorf("值为空")
	}
	if strings.Contains(value, "`") {
		parts := strings.Split(value, "`")
		if len(parts) >= 3 && isKnownGroupType(strings.TrimSpace(parts[1])) {
			return parseGroupLineBacktick(value)
		}
		if !strings.Contains(value, ",") {
			return parseGroupLineBacktick(value)
		}
	}
	return parseGroupLineComma(value)
}

// isKnownGroupType 判断字符串是否为本期支持的组类型。
func isKnownGroupType(s string) bool {
	switch GroupType(s) {
	case GroupSelect, GroupURLTest, GroupFallback, GroupLoadBalance:
		return true
	}
	return false
}

// parseGroupLineBacktick 解析 ACL4SSR 真实方言：
//
//	name`type`item1`item2`...
//	url-test/fallback:      name`type`items...`url`times
//	load-balance:           name`type`items...`url`times`strategy
func parseGroupLineBacktick(value string) (*GroupConfig, error) {
	parts := strings.Split(value, "`")
	if len(parts) < 3 {
		return nil, fmt.Errorf("字段数不足（name/type/内容至少三段）: %q", value)
	}
	gc := &GroupConfig{Name: strings.TrimSpace(parts[0])}
	if gc.Name == "" {
		return nil, fmt.Errorf("组名为空: %q", value)
	}

	typ := GroupType(strings.TrimSpace(parts[1]))
	switch typ {
	case GroupSelect, GroupURLTest, GroupFallback, GroupLoadBalance:
		gc.Type = typ
	default:
		return nil, fmt.Errorf("不支持的组类型 %q（仅支持 select/url-test/fallback/load-balance）", parts[1])
	}

	bound := len(parts)
	if typ.needsURL() {
		if len(parts) < 5 {
			return nil, fmt.Errorf("%s 组缺少 url/interval 尾参数: %q", typ, value)
		}
		if typ == GroupLoadBalance && len(parts) >= 6 {
			switch last := parts[len(parts)-1]; last {
			case "consistent-hashing", "round-robin":
				gc.Strategy = last
				bound--
			}
		}
		bound -= 2
		gc.URL = strings.TrimSpace(parts[bound])
		if gc.URL == "" {
			return nil, fmt.Errorf("%s 组 url 为空: %q", typ, value)
		}
		gc.Interval, gc.Tolerance = parseGroupTimes(parts[bound+1])
	}

	for _, item := range parts[2:bound] {
		if item = strings.TrimSpace(item); item != "" {
			gc.Items = append(gc.Items, item)
		}
	}
	if len(gc.Items) == 0 {
		return nil, fmt.Errorf("组内容为空: %q", value)
	}
	return gc, nil
}

// parseGroupLineComma 解析简化方言：name,type,item1,item2,...
// item 中反引号包裹的项视为正则，其余按 组名/DIRECT/REJECT/节点名/正则 兜底解释。
// url-test/fallback/load-balance 同样以 url、interval 收尾。
func parseGroupLineComma(value string) (*GroupConfig, error) {
	parts := strings.Split(value, ",")
	if len(parts) < 3 {
		return nil, fmt.Errorf("字段数不足（name/type/内容至少三段）: %q", value)
	}
	gc := &GroupConfig{Name: strings.TrimSpace(parts[0])}
	if gc.Name == "" {
		return nil, fmt.Errorf("组名为空: %q", value)
	}
	typ := GroupType(strings.TrimSpace(parts[1]))
	switch typ {
	case GroupSelect, GroupURLTest, GroupFallback, GroupLoadBalance:
		gc.Type = typ
	default:
		return nil, fmt.Errorf("不支持的组类型 %q（仅支持 select/url-test/fallback/load-balance）", parts[1])
	}

	bound := len(parts)
	if typ.needsURL() {
		if len(parts) < 5 {
			return nil, fmt.Errorf("%s 组缺少 url/interval 尾参数: %q", typ, value)
		}
		bound -= 2
		gc.URL = strings.TrimSpace(parts[bound])
		if gc.URL == "" {
			return nil, fmt.Errorf("%s 组 url 为空: %q", typ, value)
		}
		if iv, err := strconv.Atoi(strings.TrimSpace(parts[bound+1])); err == nil {
			gc.Interval = iv
		} else {
			return nil, fmt.Errorf("%s 组 interval 非数字: %q", typ, parts[bound+1])
		}
	}

	for _, item := range parts[2:bound] {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// 反引号包裹 → 正则项，剥掉包裹后统一加 [] 之外的语义由渲染层处理：
		// 这里转写为渲染层可识别的正则项（不带 [] 前缀即正则）
		gc.Items = append(gc.Items, strings.Trim(item, "`"))
	}
	if len(gc.Items) == 0 {
		return nil, fmt.Errorf("组内容为空: %q", value)
	}
	return gc, nil
}

// parseGroupTimes 解析 url-test 尾参 times：interval,timeout,tolerance（可缺省），
// 如 "300,,50" → interval=300, tolerance=50。对应 C++ parseGroupTimes。
func parseGroupTimes(src string) (interval, tolerance int) {
	fields := strings.Split(src, ",")
	get := func(i int) int {
		if i >= len(fields) {
			return 0
		}
		n, err := strconv.Atoi(strings.TrimSpace(fields[i]))
		if err != nil {
			return 0
		}
		return n
	}
	return get(0), get(2)
}

// parseBool 宽松解析 ini 布尔值。
func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// isAllDigits 判断字符串是否为纯数字（允许前后空白）。
func isAllDigits(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
