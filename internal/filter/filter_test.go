package filter

import (
	"testing"

	"subconv/internal/model"
)

// testNodes 构造测试节点集。
func testNodes() []model.Proxy {
	return []model.Proxy{
		{Name: "香港 01"},
		{Name: "香港 02"},
		{Name: "日本 03"},
		{Name: "美国 04"},
	}
}

// TestFilterInclude include 存在时仅保留匹配节点。
func TestFilterInclude(t *testing.T) {
	got := FilterNodes(testNodes(), "^香港", "")
	if len(got) != 2 || got[0].Name != "香港 01" || got[1].Name != "香港 02" {
		t.Errorf("include 过滤结果错误: %v", got)
	}
}

// TestFilterExclude exclude 存在时剔除匹配节点。
func TestFilterExclude(t *testing.T) {
	got := FilterNodes(testNodes(), "", "香港")
	if len(got) != 2 || got[0].Name != "日本 03" || got[1].Name != "美国 04" {
		t.Errorf("exclude 过滤结果错误: %v", got)
	}
}

// TestFilterBoth include 与 exclude 同时生效：先保留再剔除。
func TestFilterBoth(t *testing.T) {
	// 保留"香港|日本"，再剔除"日本"
	got := FilterNodes(testNodes(), "香港|日本", "日本")
	if len(got) != 2 || got[0].Name != "香港 01" {
		t.Errorf("include+exclude 组合过滤结果错误: %v", got)
	}
}

// TestFilterNoMatch include 无匹配时结果为空。
func TestFilterNoMatch(t *testing.T) {
	if got := FilterNodes(testNodes(), "新加坡", ""); len(got) != 0 {
		t.Errorf("无匹配 include 应得到空集, got %v", got)
	}
}

// TestFilterIgnoreInvalidRegex 非法正则与空串：对应条件被忽略（不过滤）。
func TestFilterIgnoreInvalidRegex(t *testing.T) {
	// 非法 RE2 正则（未闭合括号）
	if got := FilterNodes(testNodes(), "([", ""); len(got) != 4 {
		t.Errorf("非法 include 正则应被忽略, got %d 个节点", len(got))
	}
	if got := FilterNodes(testNodes(), "", "(["); len(got) != 4 {
		t.Errorf("非法 exclude 正则应被忽略, got %d 个节点", len(got))
	}
	// 空串不过滤
	if got := FilterNodes(testNodes(), "", ""); len(got) != 4 {
		t.Errorf("空条件不应过滤, got %d 个节点", len(got))
	}
}

// TestFilterRE2Unsupported RE2 不支持的语法（lookahead）编译失败 → 条件忽略。
func TestFilterRE2Unsupported(t *testing.T) {
	if got := FilterNodes(testNodes(), "香港(?= 0)", ""); len(got) != 4 {
		t.Errorf("RE2 不支持的语法应视为非法正则被忽略, got %d 个节点", len(got))
	}
}

// TestFilterEmptyInput 空输入返回空切片（非 nil 亦可，长度必须为 0）。
func TestFilterEmptyInput(t *testing.T) {
	if got := FilterNodes(nil, "x", "y"); len(got) != 0 {
		t.Errorf("空输入应返回空集, got %v", got)
	}
}
