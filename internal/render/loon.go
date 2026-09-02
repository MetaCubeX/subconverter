// loon.go 实现 Loon conf 渲染（Phase 4）。
// 输出结构：[General] 骨架（取自 base/base/loon.conf 最小版）+ [Proxy] 节点行
// + [Proxy Group] 策略组 + [Rule] 规则（复用 Clash 侧规则装载后 MATCH→FINAL 改写）。
//
// 节点行翻译对照 C++ 版 subexport.cpp 的 proxyToLoon：
//   - ss:     Name = Shadowsocks,server,port,cipher,"password"
//   - vmess:  Name = vmess,server,port,method,"uuid",over-tls=...,transport=...
//   - trojan: Name = trojan,server,port,"password"[,tls-name=...][,skip-cert-verify=...]
//   - hy2:    Name = hysteria2,server,port,"password"[,obfs=...][,obfs-password=...][,sni=...]
//
// C++ proxyToLoon 未实现 vless / anytls（两者落入 default: continue，节点被丢弃），
// 本版按 Loon 3.x 语法补齐（vless 含 REALITY 的 publicKey/shortId 键名）。
package render

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"subconv/internal/model"
	"subconv/internal/rule"
)

// loonGeneralTemplate [General] 段最小骨架，值取自 base/base/loon.conf。
const loonGeneralTemplate = `[General]
skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,e.crashlynatics.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system,119.29.29.29,223.5.5.5
allow-udp-proxy = false
host = 127.0.0.1
`

// RenderLoon 渲染完整 Loon 配置：骨架 + 节点 + 策略组 + 规则。
// 与 RenderClash 同入参风格：ACL 为 nil 时仅渲染节点段与 FINAL 兜底规则。
func RenderLoon(nodes []model.Proxy, cfg *Config) (string, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	// 节点名清洗与 Clash 侧一致（'=' 清洗 + 重名去重）
	sanitizeNodeNames(nodes)

	var buf strings.Builder
	buf.WriteString(loonGeneralTemplate)

	buf.WriteString("\n[Proxy]\n")
	for i := range nodes {
		line, ok := proxyToLoonLine(&nodes[i])
		if !ok {
			// 对齐 C++ proxyToLoon：不支持的传输类型直接跳过该节点
			log.Printf("Loon 渲染跳过节点 %q（不支持的传输类型 %q）", nodes[i].Name, nodes[i].Network)
			continue
		}
		buf.WriteString(nodes[i].Name + " = " + line + "\n")
	}

	buf.WriteString("\n[Remote Proxy]\n")

	// 策略组：复用 Clash 的组展开（[]引用/DIRECT/REJECT/正则展开 + 空组兜底 DIRECT）
	buf.WriteString("\n[Proxy Group]\n")
	groupLines, err := loonGroups(nodes, cfg.ACL)
	if err != nil {
		return "", err
	}
	for _, gl := range groupLines {
		buf.WriteString(gl + "\n")
	}

	// 规则：复用 Phase 2 的规则装载（本地 .list 展开 + 远程预取），MATCH 统一改写为 FINAL
	buf.WriteString("\n[Rule]\n")
	rules, err := renderRules(cfg.ACL)
	if err != nil {
		return "", err
	}
	for _, r := range rules {
		buf.WriteString(loonRule(r) + "\n")
	}

	buf.WriteString("\n[Remote Rule]\n")
	return buf.String(), nil
}

// loonRule 把 Clash 风格规则行改写为 Loon 语法：MATCH → FINAL
// （对齐 C++ rulesetToSurge 对 Loon 的处理），其余原样。
func loonRule(r string) string {
	if strings.HasPrefix(r, "MATCH,") {
		return "FINAL," + strings.TrimPrefix(r, "MATCH,")
	}
	return r
}

// ---------- 节点行 ----------

// proxyToLoonLine 渲染单个节点的 Loon 行（不含 "Name = " 前缀）。
// ok 为 false 表示该节点在 Loon 侧不支持（调用方跳过，对齐 C++ 的 continue）。
func proxyToLoonLine(p *model.Proxy) (string, bool) {
	switch p.Type {
	case model.TypeSS:
		return loonSS(p), true
	case model.TypeVMess:
		return loonVMess(p)
	case model.TypeTrojan:
		return loonTrojan(p), true
	case model.TypeHysteria2:
		return loonHysteria2(p), true
	case model.TypeVLESS:
		return loonVLESS(p)
	case model.TypeAnyTLS:
		return loonAnyTLS(p), true
	default:
		// 未知协议在解析层已被过滤，这里防御性跳过
		return "", false
	}
}

// loonSS C++: Shadowsocks,hostname,port,method,"password"
func loonSS(p *model.Proxy) string {
	return fmt.Sprintf("Shadowsocks,%s,%d,%s,%s", p.Server, p.Port, p.Cipher, quoteLoon(p.Password))
}

// loonVMess C++: vmess,hostname,port,method,"uuid",over-tls=...,tls-name=...,transport=...
//   - method 为 auto/空 时改写为 chacha20-ietf-poly1305（对齐 C++ 的 auto 改写）
//   - 传输层支持 tcp / ws（含 path/host），grpc 为本版补齐；
//     其余（h2/http 等）跳过节点，对齐 C++ 的 default: continue
func loonVMess(p *model.Proxy) (string, bool) {
	method := p.Security
	if method == "" || method == "auto" {
		method = "chacha20-ietf-poly1305"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "vmess,%s,%d,%s,%s,over-tls=%t", p.Server, p.Port, method, quoteLoon(p.UUID), p.TLSSecure)
	if p.TLSSecure && p.SNI != "" {
		b.WriteString(",tls-name=" + p.SNI)
	}
	switch p.Network {
	case "tcp", "":
		b.WriteString(",transport=tcp")
	case "ws":
		// C++ 对 path/host 即使为空也输出键（键名固定）
		fmt.Fprintf(&b, ",transport=ws,path=%s,host=%s", p.WSPath, p.WSHeaders["Host"])
	case "grpc":
		b.WriteString(",transport=grpc")
		if p.GRPCServiceName != "" {
			b.WriteString(",grpc-service-name=" + p.GRPCServiceName)
		}
	default:
		return "", false
	}
	if p.SkipCertVerify {
		b.WriteString(",skip-cert-verify=true")
	}
	return b.String(), true
}

// loonTrojan C++: trojan,hostname,port,"password"[,tls-name=...][,skip-cert-verify=...]
func loonTrojan(p *model.Proxy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "trojan,%s,%d,%s", p.Server, p.Port, quoteLoon(p.Password))
	if p.SNI != "" {
		b.WriteString(",tls-name=" + p.SNI)
	}
	if p.SkipCertVerify {
		b.WriteString(",skip-cert-verify=true")
	}
	return b.String()
}

// loonHysteria2 C++ 基础上追加 obfs/obfs-password（Loon 3.x 支持 salamander 混淆）：
// hysteria2,hostname,port,"password"[,obfs=...][,obfs-password=...][,sni=...][,skip-cert-verify=true]
func loonHysteria2(p *model.Proxy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "hysteria2,%s,%d,%s", p.Server, p.Port, quoteLoon(p.Password))
	if p.Hysteria2Obfs != "" {
		b.WriteString(",obfs=" + p.Hysteria2Obfs)
		if p.Hysteria2ObfsPassword != "" {
			b.WriteString(",obfs-password=" + p.Hysteria2ObfsPassword)
		}
	}
	if p.SNI != "" {
		b.WriteString(",sni=" + p.SNI)
	}
	if p.SkipCertVerify {
		b.WriteString(",skip-cert-verify=true")
	}
	return b.String()
}

// loonVLESS Loon 3.x 语法（C++ proxyToLoon 未实现，本版补齐）：
//
//	vless,server,port,uuid,tls=true,sni=...,flow=...,transport=tcp|ws|grpc
//	  ws:  追加 ws-path=...、ws-headers=Host:...
//	  grpc: 追加 grpc-service-name=...
//	  REALITY: publicKey=...、shortId=...（Loon 3.x 键名）
func loonVLESS(p *model.Proxy) (string, bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "vless,%s,%d,%s,tls=%t", p.Server, p.Port, quoteLoon(p.UUID), p.TLSSecure)
	if p.SNI != "" {
		b.WriteString(",sni=" + p.SNI)
	}
	if p.Flow != "" {
		b.WriteString(",flow=" + p.Flow)
	}
	switch p.Network {
	case "tcp", "":
		b.WriteString(",transport=tcp")
	case "ws":
		b.WriteString(",transport=ws")
		if p.WSPath != "" {
			b.WriteString(",ws-path=" + p.WSPath)
		}
		if host := p.WSHeaders["Host"]; host != "" {
			b.WriteString(",ws-headers=Host:" + host)
		}
	case "grpc":
		b.WriteString(",transport=grpc")
		if p.GRPCServiceName != "" {
			b.WriteString(",grpc-service-name=" + p.GRPCServiceName)
		}
	default:
		return "", false
	}
	if p.PublicKey != "" {
		b.WriteString(",publicKey=" + p.PublicKey)
		if p.ShortID != "" {
			b.WriteString(",shortId=" + p.ShortID)
		}
	}
	if p.SkipCertVerify {
		b.WriteString(",skip-cert-verify=true")
	}
	return b.String(), true
}

// loonAnyTLS Loon 3.x 语法（C++ proxyToLoon 未实现，本版补齐）：
// anytls,server,port,"password"[,sni=...][,skip-cert-verify=true]
func loonAnyTLS(p *model.Proxy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "anytls,%s,%d,%s", p.Server, p.Port, quoteLoon(p.Password))
	if p.SNI != "" {
		b.WriteString(",sni=" + p.SNI)
	}
	if p.SkipCertVerify {
		b.WriteString(",skip-cert-verify=true")
	}
	return b.String()
}

// quoteLoon 为值加双引号（对齐 C++：密码/UUID 一律加引号，兼容含逗号的值）。
func quoteLoon(v string) string {
	return `"` + v + `"`
}

// ---------- 策略组 ----------

// loonGroups 生成 [Proxy Group] 段的行，组展开复用 Clash 侧 expandGroupItems。
// 行语法对照 C++ proxyToLoon：
//   - select:       Name = select,成员1,成员2,...
//   - url-test:     Name = url-test,成员...[,tolerance=N],url=...,interval=N —— 尾参在成员后
//   - fallback:     Name = fallback,成员...,url=...,interval=N
//   - load-balance: Name = load-balance,成员...,url=...,interval=N,algorithm=round-robin|pcc
func loonGroups(nodes []model.Proxy, acl *rule.ACLConfig) ([]string, error) {
	if acl == nil || len(acl.Groups) == 0 {
		return nil, nil
	}

	groupNames := make(map[string]bool, len(acl.Groups))
	for _, g := range acl.Groups {
		groupNames[g.Name] = true
	}

	var lines []string
	for _, g := range acl.Groups {
		members, err := expandGroupItems(g, nodes, groupNames)
		if err != nil {
			return nil, fmt.Errorf("策略组 %q: %w", g.Name, err)
		}

		var b strings.Builder
		b.WriteString(g.Name + " = " + string(g.Type))
		for _, m := range members {
			b.WriteString("," + m)
		}
		if g.Type != rule.GroupSelect {
			// C++ 固定输出 url=...,interval=...（interval 即使为 0 也输出）
			b.WriteString(",url=" + g.URL + ",interval=" + strconv.Itoa(g.Interval))
			switch g.Type {
			case rule.GroupLoadBalance:
				// consistent-hashing → pcc（对齐 C++ BalanceStrategy 映射）
				algorithm := "pcc"
				if g.Strategy == "round-robin" {
					algorithm = "round-robin"
				}
				b.WriteString(",algorithm=" + algorithm)
			case rule.GroupURLTest:
				if g.Tolerance > 0 {
					b.WriteString(",tolerance=" + strconv.Itoa(g.Tolerance))
				}
			}
		}
		lines = append(lines, b.String())
	}
	return lines, nil
}
