# subconverter-go 重写计划

> 分支：`golang-rewrite`
> 目标：用 Go 重写 subconverter，只保留 **Clash + Loon** 两种输出格式
> 原则：小步快跑，每个阶段可独立验证，随时可对拍回退

## 1. 背景与动机

- C++ 版维护成本高：yaml-cpp 无强制引号能力（`29845e28` 类型歧义修复需要 hack）、
  交叉编译痛苦、依赖链（quickjs/libcron/toml11）笨重

- 实际使用场景收窄：只输出 Clash（mihomo 生态）和 Loon，输入为机场订阅
  （vless/REALITY、anytls、ss、trojan、hysteria2、vmess）

- Go 收益：单二进制交叉编译、`yaml.v3` 原生控制引号、新协议当天可加

## 2. 范围

### In Scope

| 模块       | 内容                                                                           |
| -------- | ---------------------------------------------------------------------------- |
| 输入解析     | vless(+REALITY)、vmess、ss、trojan、hysteria2、anytls；订阅形式：base64 明文列表、Clash YAML |
| 输出渲染     | Clash（mihomo，含 rule-providers）、Loon                                          |
| 规则系统     | 复用现有 `base/rules/*.list` 与 `base/config/ACL4SSR*.ini`（策略组定义解析后重新渲染）          |
| HTTP API | `/sub` 参数兼容现有用法（target/url/config/include/exclude/emoji 等）                   |
| 部署       | Docker 多阶段构建，镜像 < 30MB                                                       |

### Out of Scope（明确不做）

- Surge/Quantumult(X)/Surfboard/Mellow/SSD/SSR 等其他 16 种输出格式

- JS 脚本引擎（QuickJS/goja）、定时任务（cron）、模板引擎（inja）

- gist 上传、managed config 更新链接

- 本地生成模式（`-g`）、配置档案（profile）

- PCRE2 正则：输入的正则按 RE2 语法处理，文档中注明差异

## 3. 目标架构

```
subconverter-go/
├── cmd/subconv/main.go        # 入口：HTTP 服务 / 版本信息
├── internal/
│   ├── model/proxy.go         # 核心数据模型（见 §3.1）
│   ├── parser/                # 输入侧
│   │   ├── vless.go           # vless:// URI + REALITY 参数
│   │   ├── vmess.go           # vmess:// base64 JSON（含历史字段变体）
│   │   ├── ss.go / trojan.go / hysteria2.go / anytls.go
│   │   └── subscription.go    # 订阅内容识别（base64/明文/YAML）+ UA 策略
│   ├── fetch/fetch.go         # 订阅拉取（超时/重试/缓存/subscription-userinfo 头提取）
│   ├── render/
│   │   ├── clash.go           # Clash YAML 渲染（yaml.v3 Node 精确控制样式）
│   │   ├── loon.go            # Loon conf 渲染
│   │   └── ruleset.go         # .list 规则文件装载与分类
│   ├── rule/ini.go            # ACL4SSR ini → 策略组/规则结构
│   ├── filter/filter.go       # include/exclude 正则过滤、重命名、emoji
│   └── server/handler.go      # /sub handler，参数解析与分发
├── base/                      # 直接复用 C++ 版资产（rules/、config/*.ini、emoji 映射）
├── testdata/                  # 对拍样本（真实订阅脱敏后的固定样本）
└── Dockerfile
```

### 3.1 核心数据模型（先于一切）

```go
type Proxy struct {
    Type      ProxyType  // VLESS, VMess, SS, Trojan, Hysteria2, AnyTLS, ...
    Name      string
    Server    string
    Port      int
    UDP       *bool      // 三态：nil = 未设置
    Group     string

    // VLESS / REALITY
    UUID, Flow, PublicKey, ShortID string
    ClientFingerprint, SNI, ALPN   []string / string...

    // VMess
    AlterID, Security string

    // SS / Trojan / AnyTLS
    Cipher, Password string

    // 传输层
    Network    string  // tcp/ws/grpc/http/h2
    WSOpts, GRPCOpts ...

    // TLS
    TLSSecure, SkipCertVerify bool
}
```

设计要点：

- **字段三态**：用 `*bool` 等区分"未设置/显式 false"，对应 C++ tribool——
  渲染时只输出显式设置的字段

- **ShortID 入模型前即清洗**：`sanitizeShortID()` 逻辑内置到 parser 层
  （奇数补零、非 hex 丢弃），渲染层不再关心

- **渲染层强制字符串**：yaml.v3 `Node.Style = DoubleQuotedStyle`，
  彻底杜绝类型歧义（C++ 版踩过的坑全部免疫）

## 4. 阶段计划

### Phase 0：项目初始化（0.5 天）

- [ ] `git mv src CMakeLists.txt cmake scripts → archive/`（保留 base/ 在根，
  Go 版直接复用；.github/workflows 的构建文件一并归档）

- [ ] `go mod init`，目录骨架，`base/` 引用关系确认

- [ ] 最小 main.go：`/version` 端点跑起来

- [ ] 对拍基础设施：`cmd/compare/main.go` —— 同一订阅分别请求
  `localhost:25500`（C++ 版，作为 golden reference）和 Go 版，
  解析后逐节点 diff

**验收**：`curl :25600/version` 返回；`go test ./...` 空.

### Phase 1：输入解析（3-4 天）— 价值最高，先做

- [ ] vless URI 解析（含 REALITY 全参数：pbk/sid/fp/sni/flow/xtls）+ 单测

- [ ] vmess 解析（base64 JSON，新旧字段变体）+ 单测

- [ ] ss / trojan / hysteria2 / anytls 解析 + 单测

- [ ] 订阅内容识别：base64 / 明文行 / Clash YAML（读 YAML 比输出简单）

- [ ] 单测数据：**从 tuotuoyun 真实订阅抽取 23 个 REALITY 节点**脱敏入库
  （含 3 个 `29845e28`、1 个 `40452118`——即现成的回归用例）

**验收**：解析测试全绿；输入样本 → `[]Proxy` 与 C++ 版解析结果逐字段一致。

### Phase 2：Clash 渲染（4-5 天）— 工作量最大

- [ ] yaml.v3 渲染：节点段（每协议一节），REALITY 字段全量 + 强制引号

- [ ] ACL4SSR ini 解析：`custom_proxy_group` / `ruleset` / `[common]`

- [ ] 策略组生成：select/url-test/fallback/load-balance + 正则匹配组

- [ ] 规则装载：本地 `base/rules/*.list` + 远程规则 URL（缓存）

- [ ] include/exclude 过滤、emoji 标签、重命名正则

**验收**：对拍 C++ 版 —— 同订阅同参数，两版输出经 mihomo `-t` 校验均通过；
节点数、策略组结构、规则条数一致（YAML 序列化细节允许差异，语义等价即可）。

### Phase 3：订阅获取（1 天）

- [ ] HTTP 拉取：自定义 UA（clash.meta）、超时、失败重试

- [ ] `subscription-userinfo` 响应头解析（流量信息）

- [ ] 简单磁盘缓存（TTL 可配）

**验收**：真实 tuotuoyun 订阅全链路：拉取→解析→过滤→渲染。

### Phase 4：Loon 渲染（2 天）

- [ ] Loon conf 语法：`[Proxy]` 节点行（各协议三段式）、`[Proxy Group]`、
  `[Rule]` + `[Remote Rule]`

- [ ] REALITY 在 Loon 的字段映射（对照 C++ 版 `proxyToLoon` 翻译，
  参考 Loon 官方文档核对）

- [ ] 基础模板 `base/base/loon.conf` 模板化

**验收**：Loon 侧无本地内核可校验 —— 输出与 C++ 版 Loon 输出 diff，
差异逐条确认语义等价或有意改进。

### Phase 5：HTTP 服务与参数兼容（1-2 天）

- [ ] `/sub` 完整参数集：target/url/config/include/exclude/list/emoji/sort/...

- [ ] 错误响应格式对齐（C++ 版的文本错误）

- [ ] pref 配置（toml，viper）：监听地址/端口/API token/缓存

- [ ] `/getruleset`、`/readconf`、`/flushcache` 管理端点

**验收**：把 Clash Verge Rev 的订阅 URL 从 25500 切到 25600，刷新可用。

### Phase 6：部署收尾（1 天）

- [ ] 多阶段 Dockerfile（golang builder + alpine/distroless）

- [ ] GHCR workflow（复用现有 docker.yml 改造）

- [ ] README-go.md：使用说明、参数差异（RE2 正则）、迁移指引

**验收**：镜像构建推送成功，容器跑通全链路。

### 里程碑总览

```
Phase 0 ── Phase 1 ── Phase 2 ── Phase 3 ── Phase 4 ── Phase 5 ── Phase 6
骨架       解析        Clash渲染    订阅获取     Loon        API兼容     部署
0.5d       3-4d        4-5d        1d          2d          1-2d        1d
                                    ↑                                    ↑
                              真实订阅全链路                    Clash Verge 切换
```

预计总量 13-16 个工作日（业余时间折算约 4-6 周）。

## 5. 关键风险与对策

| 风险                             | 对策                                                                  |
| ------------------------------ | ------------------------------------------------------------------- |
| Clash 输出与 C++ 版语义漂移（字段命名/结构细节） | 每阶段对拍；`29845e28` 等已知坑写成固定回归用例                                       |
| Loon 无内核可验证                    | 与 C++ 版输出 diff + Loon 手动导入真机测试                                      |
| ACL4SSR ini 方言细节多（正则组/条件组语法）   | 只支持实际用到的 ACL4SSR\_Online 系；不认识的语法 fail-fast 报错                      |
| RE2 不支持 lookahead              | include/exclude 建议按子串/前缀写；文档注明；如真需要再引入 `github.com/wasilibs/go-re2` |
| 机场出新协议                         | parser 接口约定：一个协议一个文件 + 注册表，新增零侵入                                    |

## 6. 对拍与回归策略（贯穿全程）

1. **golden reference**：C++ 版（localhost:25500，当前 `subconverter-test` 容器）
   冻结行为作为基准
2. **固定样本集**：`testdata/tuotuoyun.txt`（脱敏 23 节点）+ 构造边界样本
   （纯数字密码、科学计数法 short-id、奇数长度 sid、无 sid REALITY）
3. **每阶段出口**：`make compare` 输出 diff 报告，语义等价即过
4. **mihomo** **`-t`**：Clash 输出一律过内核校验（docker run 一次的事）

## 7. 变更说明

- `archive/` 内 C++ 代码只读参考，不再构建；`master` 分支保留 C++ 版可用状态

- 重写完成后 `golang-rewrite` 分支合回 master，C++ 版 Dockerfile/workflow 保留在
  archive 中作为历史

