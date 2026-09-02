package render

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"subconv/internal/model"
	"subconv/internal/rule"
)

// groupTestNodes 三个测试节点：两个香港、一个日本。
func groupTestNodes() []model.Proxy {
	return []model.Proxy{
		{Type: model.TypeSS, Name: "香港01", Server: "1.1.1.1", Port: 1, Cipher: "aes-128-gcm", Password: "a"},
		{Type: model.TypeSS, Name: "香港02", Server: "2.2.2.2", Port: 2, Cipher: "aes-128-gcm", Password: "b"},
		{Type: model.TypeSS, Name: "日本01", Server: "3.3.3.3", Port: 3, Cipher: "aes-128-gcm", Password: "c"},
	}
}

// TestGroupRegexExpansionBacktick 反引号方言：正则项按节点名非锚定匹配展开。
func TestGroupRegexExpansionBacktick(t *testing.T) {
	acl := &rule.ACLConfig{Groups: []rule.GroupConfig{
		{Name: "节点选择", Type: rule.GroupSelect, Items: []string{"香港"}},
	}}
	groups, err := renderGroups(groupTestNodes(), acl)
	if err != nil {
		t.Fatalf("生成策略组失败: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("组数量 = %d, want 1", len(groups))
	}
	proxies := groups[0].Content
	// 定位 proxies 序列（name/type/proxies 三键）
	var names []string
	for i := 0; i+1 < len(proxies); i += 2 {
		if proxies[i].Value == "proxies" {
			for _, item := range proxies[i+1].Content {
				names = append(names, item.Value)
			}
		}
	}
	if len(names) != 2 || names[0] != "香港01" || names[1] != "香港02" {
		t.Errorf("正则展开结果 = %v, want [香港01 香港02]", names)
	}
}

// TestGroupRegexExpansionComma 简化方言：反引号包裹的正则项同样展开。
func TestGroupRegexExpansionComma(t *testing.T) {
	acl, err := rule.ParseINI("[custom]\ncustom_proxy_group=节点选择,select,`香港`\n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	groups, err := renderGroups(groupTestNodes(), acl)
	if err != nil {
		t.Fatalf("生成策略组失败: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("组数量 = %d, want 1", len(groups))
	}
	var names []string
	proxies := groups[0].Content
	for i := 0; i+1 < len(proxies); i += 2 {
		if proxies[i].Value == "proxies" {
			for _, item := range proxies[i+1].Content {
				names = append(names, item.Value)
			}
		}
	}
	if len(names) != 2 || names[0] != "香港01" || names[1] != "香港02" {
		t.Errorf("简化方言正则展开结果 = %v, want [香港01 香港02]", names)
	}
}

// TestGroupRegexFullRender 走完整 RenderClash 链路验证正则组展开的 YAML 结构。
func TestGroupRegexFullRender(t *testing.T) {
	acl, err := rule.ParseINI("[custom]\ncustom_proxy_group=节点选择,select,`香港`\n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, err := RenderClash(groupTestNodes(), &Config{ACL: acl})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	var doc clashDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("输出不是合法 YAML: %v", err)
	}
	if len(doc.Groups) != 1 {
		t.Fatalf("proxy-groups 数 = %d, want 1", len(doc.Groups))
	}
	proxies := doc.Groups[0]["proxies"].([]any)
	if len(proxies) != 2 || proxies[0] != "香港01" || proxies[1] != "香港02" {
		t.Errorf("组展开 = %v, want [香港01 香港02]", proxies)
	}
}

// TestGroupRefValidation 组引用校验：引用不存在的组 fail-fast。
func TestGroupRefValidation(t *testing.T) {
	acl := &rule.ACLConfig{Groups: []rule.GroupConfig{
		{Name: "组A", Type: rule.GroupSelect, Items: []string{"[]不存在的组"}},
	}}
	if _, err := renderGroups(groupTestNodes(), acl); err == nil {
		t.Fatal("引用不存在的组应返回 error")
	} else if !strings.Contains(err.Error(), "不存在的组") {
		t.Errorf("错误信息应指明缺失的组: %v", err)
	}
}

// TestGroupRefValidationOK 合法组引用（含前后定义顺序）与 DIRECT/REJECT。
func TestGroupRefValidationOK(t *testing.T) {
	acl := &rule.ACLConfig{Groups: []rule.GroupConfig{
		{Name: "组A", Type: rule.GroupSelect, Items: []string{"[]组B", "[]DIRECT", "[]REJECT"}},
		{Name: "组B", Type: rule.GroupURLTest, Items: []string{".*"}, URL: "http://www.gstatic.com/generate_204", Interval: 300, Tolerance: 50},
	}}
	groups, err := renderGroups(groupTestNodes(), acl)
	if err != nil {
		t.Fatalf("合法引用不应报错: %v", err)
	}
	var names []string
	proxies := groups[0].Content
	for i := 0; i+1 < len(proxies); i += 2 {
		if proxies[i].Value == "proxies" {
			for _, item := range proxies[i+1].Content {
				names = append(names, item.Value)
			}
		}
	}
	// 组B + DIRECT + REJECT（.* 正则无命中节点前已显式引用）
	if len(names) != 3 || names[0] != "组B" || names[1] != "DIRECT" || names[2] != "REJECT" {
		t.Errorf("组引用展开 = %v, want [组B DIRECT REJECT]", names)
	}
}

// TestGroupURLTestFields url-test 输出 url/interval/tolerance，load-balance 输出 strategy。
func TestGroupURLTestFields(t *testing.T) {
	acl := &rule.ACLConfig{Groups: []rule.GroupConfig{
		{Name: "自动", Type: rule.GroupURLTest, Items: []string{".*"},
			URL: "http://www.gstatic.com/generate_204", Interval: 300, Tolerance: 50},
		{Name: "负载", Type: rule.GroupLoadBalance, Items: []string{".*"},
			URL: "http://www.gstatic.com/generate_204", Interval: 60},
	}}
	groups, err := renderGroups(groupTestNodes(), acl)
	if err != nil {
		t.Fatalf("生成策略组失败: %v", err)
	}
	getFields := func(g yaml.Node) map[string]any {
		out := map[string]any{}
		for i := 0; i+1 < len(g.Content); i += 2 {
			out[g.Content[i].Value] = g.Content[i+1].Value
		}
		return out
	}
	f0 := getFields(groups[0])
	if f0["type"] != "url-test" || f0["url"] != "http://www.gstatic.com/generate_204" ||
		f0["interval"] != "300" || f0["tolerance"] != "50" {
		t.Errorf("url-test 字段错误: %v", f0)
	}
	f1 := getFields(groups[1])
	if f1["type"] != "load-balance" || f1["strategy"] != "consistent-hashing" || f1["interval"] != "60" {
		t.Errorf("load-balance 字段错误: %v", f1)
	}
}

// TestGroupEmptyFallbackDIRET 正则零命中时组内兜底 DIRECT。
func TestGroupEmptyFallbackDIRET(t *testing.T) {
	acl := &rule.ACLConfig{Groups: []rule.GroupConfig{
		{Name: "美国", Type: rule.GroupSelect, Items: []string{"美国"}},
	}}
	groups, err := renderGroups(groupTestNodes(), acl)
	if err != nil {
		t.Fatalf("生成策略组失败: %v", err)
	}
	var names []string
	proxies := groups[0].Content
	for i := 0; i+1 < len(proxies); i += 2 {
		if proxies[i].Value == "proxies" {
			for _, item := range proxies[i+1].Content {
				names = append(names, item.Value)
			}
		}
	}
	if len(names) != 1 || names[0] != "DIRECT" {
		t.Errorf("零命中应兜底 DIRECT, got %v", names)
	}
}
