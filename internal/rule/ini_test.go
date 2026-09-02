package rule

import (
	"os"
	"testing"
)

// testACLINI 读取测试固定样本 testdata/acl_mini.ini（语义对齐
// ACL4SSR_Online_Mini.ini：5 组 + 10 远程 ruleset + GEOIP/FINAL 内联，
// 全部远程 URL，不依赖任何本地规则资产）。
func testACLINI(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../testdata/acl_mini.ini")
	if err != nil {
		t.Fatalf("读取测试配置失败: %v", err)
	}
	return string(data)
}

// TestParseINIMiniFile 解析测试样本：策略组/规则集数量、关键结构正确。
func TestParseINIMiniFile(t *testing.T) {
	cfg, err := ParseINI(testACLINI(t))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 固定 5 组 / 11 条 ruleset（9 远程 + GEOIP + FINAL）
	if len(cfg.Groups) != 5 {
		t.Errorf("策略组数量 = %d, want 5", len(cfg.Groups))
	}
	if len(cfg.Rulesets) != 11 {
		t.Errorf("规则集数量 = %d, want 11", len(cfg.Rulesets))
	}

	// 第 1 组：🚀 节点选择 select，内容 [自动选择引用 / DIRECT / 全部节点正则]
	g0 := cfg.Groups[0]
	if g0.Name != "🚀 节点选择" || g0.Type != GroupSelect {
		t.Errorf("第 1 组 = %s/%s, want 🚀 节点选择/select", g0.Name, g0.Type)
	}
	wantItems := []string{"[]♻️ 自动选择", "[]DIRECT", ".*"}
	if len(g0.Items) != len(wantItems) {
		t.Fatalf("第 1 组内容数 = %d, want %d", len(g0.Items), len(wantItems))
	}
	for i, w := range wantItems {
		if g0.Items[i] != w {
			t.Errorf("第 1 组内容[%d] = %q, want %q", i, g0.Items[i], w)
		}
	}

	// 第 2 组：♻️ 自动选择 url-test，url/interval/tolerance 解析正确
	g1 := cfg.Groups[1]
	if g1.Name != "♻️ 自动选择" || g1.Type != GroupURLTest {
		t.Errorf("第 2 组 = %s/%s, want ♻️ 自动选择/url-test", g1.Name, g1.Type)
	}
	if g1.URL != "http://www.gstatic.com/generate_204" {
		t.Errorf("第 2 组 URL = %q", g1.URL)
	}
	if g1.Interval != 300 {
		t.Errorf("第 2 组 Interval = %d, want 300（times \"300,,50\" 首段）", g1.Interval)
	}
	if g1.Tolerance != 50 {
		t.Errorf("第 2 组 Tolerance = %d, want 50（times \"300,,50\" 第三段）", g1.Tolerance)
	}
	if len(g1.Items) != 1 || g1.Items[0] != ".*" {
		t.Errorf("第 2 组内容 = %v, want [.*]", g1.Items)
	}

	// 第 5 组：🛑 全球拦截 select [REJECT DIRECT]
	g4 := cfg.Groups[4]
	if g4.Name != "🛑 全球拦截" || len(g4.Items) != 2 ||
		g4.Items[0] != "[]REJECT" || g4.Items[1] != "[]DIRECT" {
		t.Errorf("第 5 组结构错误: %+v", g4)
	}

	// 规则集：首条远程、含 GEOIP 内联与 FINAL 内联
	rs0 := cfg.Rulesets[0]
	if rs0.Group != "🎯 全球直连" || rs0.Path != "https://example.com/rules/LocalAreaNetwork.list" || rs0.Inline != "" {
		t.Errorf("第 1 条规则集结构错误: %+v", rs0)
	}
	hasGEOIP, hasFinal := false, false
	for _, rs := range cfg.Rulesets {
		switch {
		case rs.Inline == "GEOIP,CN":
			hasGEOIP = true
			if rs.Group != "🎯 全球直连" {
				t.Errorf("GEOIP 规则集组名 = %q", rs.Group)
			}
		case rs.Inline == "FINAL":
			hasFinal = true
			if rs.Group != "🐟 漏网之鱼" {
				t.Errorf("FINAL 规则集组名 = %q", rs.Group)
			}
		}
	}
	if !hasGEOIP || !hasFinal {
		t.Errorf("内联规则解析缺失: GEOIP=%v FINAL=%v", hasGEOIP, hasFinal)
	}

	if !cfg.EnableRuleGen || !cfg.OverwriteRules {
		t.Errorf("enable_rule_generator/overwrite_original_rules 未解析: %+v", cfg)
	}
}

// TestParseINIBacktickDialect 反引号方言细节：load-balance strategy、无 group 的 ruleset、interval 尾参。
func TestParseINIBacktickDialect(t *testing.T) {
	content := `
[custom]
ruleset=组A,https://example.com/rules/BanAD.list,86400
ruleset=https://example.com/rules/LocalAreaNetwork.list
ruleset=组B,[]DST-PORT,443
custom_proxy_group=负载均衡` + "`" + `load-balance` + "`" + `.*` + "`" + `http://www.gstatic.com/generate_204` + "`" + `300,,50` + "`" + `round-robin
`
	cfg, err := ParseINI(content)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(cfg.Rulesets) != 3 {
		t.Fatalf("规则集数量 = %d, want 3", len(cfg.Rulesets))
	}
	if cfg.Rulesets[0].Path != "https://example.com/rules/BanAD.list" {
		t.Errorf("带 interval 的路径被污染: %+v", cfg.Rulesets[0])
	}
	if cfg.Rulesets[1].Group != "" || cfg.Rulesets[1].Path != "https://example.com/rules/LocalAreaNetwork.list" {
		t.Errorf("无 group 前缀 ruleset 解析错误: %+v", cfg.Rulesets[1])
	}
	if cfg.Rulesets[2].Inline != "DST-PORT,443" || cfg.Rulesets[2].Group != "组B" {
		t.Errorf("内联 DST-PORT 解析错误: %+v", cfg.Rulesets[2])
	}

	if len(cfg.Groups) != 1 {
		t.Fatalf("策略组数量 = %d, want 1", len(cfg.Groups))
	}
	g := cfg.Groups[0]
	if g.Type != GroupLoadBalance || g.Strategy != "round-robin" {
		t.Errorf("load-balance 组解析错误: %+v", g)
	}
	if g.URL != "http://www.gstatic.com/generate_204" || g.Interval != 300 || g.Tolerance != 50 {
		t.Errorf("load-balance 尾参解析错误: %+v", g)
	}
	if len(g.Items) != 1 || g.Items[0] != ".*" {
		t.Errorf("load-balance 内容解析错误: %+v", g.Items)
	}
}

// TestParseINICommaDialect 简化方言（逗号分隔 + 反引号正则项）。
func TestParseINICommaDialect(t *testing.T) {
	content := `[custom]
custom_proxy_group=节点选择,select,[]DIRECT,` + "`" + `香港` + "`" + `
custom_proxy_group=自动测速,url-test,` + "`" + `.*` + "`" + `,http://www.gstatic.com/generate_204,300
`
	cfg, err := ParseINI(content)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(cfg.Groups) != 2 {
		t.Fatalf("策略组数量 = %d, want 2", len(cfg.Groups))
	}
	g0 := cfg.Groups[0]
	if g0.Name != "节点选择" || g0.Type != GroupSelect || len(g0.Items) != 2 {
		t.Errorf("select 组解析错误: %+v", g0)
	}
	if g0.Items[0] != "[]DIRECT" || g0.Items[1] != "香港" {
		t.Errorf("反引号正则项应去包裹保留正则: %v", g0.Items)
	}
	g1 := cfg.Groups[1]
	if g1.Type != GroupURLTest || g1.URL != "http://www.gstatic.com/generate_204" || g1.Interval != 300 {
		t.Errorf("url-test 组解析错误: %+v", g1)
	}
}

// TestParseINIErrors 非法语法 fail-fast。
func TestParseINIErrors(t *testing.T) {
	cases := map[string]string{
		"未知组类型":       "[custom]\ncustom_proxy_group=名`smart`.*\n",
		"组字段不足":       "[custom]\ncustom_proxy_group=名`select`\n",
		"url-test缺尾参": "[custom]\ncustom_proxy_group=名`url-test`.*\n",
		"未知键":         "[custom]\nunknown_key=value\n",
		"未知段":         "[common]\nfoo=bar\n",
		"缺等号":         "[custom]\n没有等号的行\n",
		"空ruleset":    "[custom]\nruleset=\n",
	}
	for name, content := range cases {
		if _, err := ParseINI(content); err == nil {
			t.Errorf("%s: 应返回 error", name)
		}
	}
}

// TestParseGroupTimes times 串解析（C++ parseGroupTimes 对齐）。
func TestParseGroupTimes(t *testing.T) {
	cases := []struct {
		in                  string
		interval, tolerance int
	}{
		{"300,,50", 300, 50},
		{"300", 300, 0},
		{"", 0, 0},
		{"abc,1,2", 0, 2},
	}
	for _, c := range cases {
		iv, tol := parseGroupTimes(c.in)
		if iv != c.interval || tol != c.tolerance {
			t.Errorf("parseGroupTimes(%q) = (%d,%d), want (%d,%d)", c.in, iv, tol, c.interval, c.tolerance)
		}
	}
}
