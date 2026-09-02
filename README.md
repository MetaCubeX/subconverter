# subconverter

代理订阅转换服务，**Go 实现**（原 C++ 版代码归档于 `archive/`，仅作参考不再构建）。
面向个人自用场景：**输入机场订阅（vless/REALITY、anytls、ss、trojan、hysteria2、vmess），
输出 Clash（mihomo）与 Loon 两种格式**。
外配置与规则集运行时从 ACL4SSR 等仓库动态拉取，镜像不含规则资产。

## 快速开始（本地部署三行命令）

```bash
docker build -t subconv-go .
docker run -d --name subconv -p 25600:25600 subconv-go
curl "http://localhost:25600/sub?target=clash&url=<订阅地址URL编码>"
```

不带 Docker 直接运行（需 Go 1.25+，工作目录为仓库根）：

```bash
go build -o subconv . && ./subconv          # 默认监听 :25600
```

外配置（ACL ini）与规则集均在**运行时远程拉取**（进程内缓存，重启后刷新）：
镜像不含任何规则资产，拉取失败直接返回 400 报错（不做本地兜底）。

## `/sub` 参数表

| 参数         | 必填 | 说明                                                                                                                                                                                                       |
| ---------- | -- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target`   | 是  | 输出格式：`clash`（mihomo YAML）/ `loon`（Loon conf）。其他值返回 400                                                                                                                                                   |
| `url`      | 是  | 订阅地址或节点链接，`\|` 分隔多段；节点链接与 http(s) 订阅地址可混合。多个订阅按序合并节点；任一段拉取/解析失败整体返回 400（对齐 C++ 严格行为）                                                                                                                     |
| `config`   | 否  | 规则/策略组外配置，**仅支持完整 http(s) URL**（拉取失败返回 400）。默认为 [ACL4SSR\_Online\_Full.ini](https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Full.ini)，需要特定配置时传该文件的完整 URL |
| `include`  | 否  | 保留节点的正则（按节点名匹配）                                                                                                                                                                                          |
| `exclude`  | 否  | 剔除节点的正则（按节点名匹配）；与 `include` 可同时生效                                                                                                                                                                        |
| `ua`       | 否  | 拉取订阅使用的 User-Agent，默认 `clash.meta`                                                                                                                                                                       |
| `filename` | 否  | 响应 `Content-Disposition` 附件文件名                                                                                                                                                                           |

订阅响应携带的 `subscription-userinfo` 头会解析后以 `Subscription-UserInfo` 头回传给客户端。

示例：

```
/sub?target=loon&url=https%3A%2F%2Fexample.com%2Fsub&exclude=%E6%97%A5%E6%9C%AC

# 指定特定外配置（config 必须是完整 URL）
/sub?target=clash&url=<订阅URL>&config=https%3A%2F%2Fraw.githubusercontent.com%2FACL4SSR%2FACL4SSR%2Frefs%2Fheads%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online_Mini.ini
```

## 输入侧支持的协议

| 协议        | 链接形态                                                    | 备注                       |
| --------- | ------------------------------------------------------- | ------------------------ |
| vless     | `vless://uuid@host:port?...`（含 REALITY：pbk/sid/fp/flow） | short-id 原样透传，合法性由下游内核判断 |
| vmess     | `vmess://` base64 JSON                                  | 新旧字段变体兼容                 |
| ss        | `ss://`                                                 | 明文与 base64 用户信息均可        |
| trojan    | `trojan://`                                             | <br />                   |
| hysteria2 | `hysteria2://` / `hy2://`                               | salamander 混淆、端口跳跃       |
| anytls    | `anytls://`                                             | <br />                   |

订阅内容支持：base64 列表、明文逐行链接、Clash YAML（含 `Proxy`/`proxies` 两种键名）。

## RE2 正则限制（重要）

Go 标准库正则为 **RE2** 语法，与 C++ 版的 PCRE2 相比：

- **不支持** lookahead/lookbehind（`(?=...)`、`(?!...)`、`(?<=...)`、`(?<!...)`）与反向引用（`\1`）

- **不受影响**：子串、前缀/后缀、字符类、量词、分组捕获等常用写法

因此 `include`/`exclude` 及外配置中的节点匹配正则请按子串/前缀风格书写；
含 lookahead 的正则会静默失效（该条件被忽略）而非报错。若确需 PCRE 语法，后续可引入 `github.com/wasilibs/go-re2`。

## 与 C++ 版的差异摘要

| 方面                | C++ 版                                | Go 版                                                        |
| ----------------- | ------------------------------------ | ----------------------------------------------------------- |
| 输出格式              | 18 种（Surge/QuantumultX/Sing-box/...） | 仅 clash / loon                                              |
| 脚本/模板引擎           | QuickJS、libcron、inja 模板              | 不支持（Out of Scope）                                           |
| YAML 引擎           | yaml-cpp，无强制引号（`29845e28` 需 hack 修复） | yaml.v3 Node 强制 DoubleQuotedStyle，类型歧义从根上免疫                 |
| short-id 校验       | 渲染期清洗（奇数补零/非法丢弃）                     | 不校验，原样透传（仍强制双引号防 YAML 类型歧义）                                 |
| 正则引擎              | PCRE2                                | RE2（见上文限制）                                                  |
| Loon vless/anytls | proxyToLoon 未实现（节点被丢弃）               | 按 Loon 3.x 语法补齐（含 REALITY `publicKey`/`shortId`）            |
| 订阅拉取              | libcurl（全局 UA、缓存 TTL、代理规则）           | net/http（默认 UA clash.meta、10s 超时、单次重试、gzip 解压、userinfo 头回传） |
| 部署                | 静态依赖链较重，交叉编译复杂                       | 单二进制 + base/ 目录，多阶段 Docker 构建                               |
| 本地生成/档案           | `-g`、profile、gist 上传、managed config  | 不支持（Out of Scope）                                           |

## 开发

```bash
go mod tidy && go build ./... && go vet ./... && go test ./...
```

- `internal/parser` 输入解析（Phase 1）、`internal/render` Clash/Loon 渲染与规则装载（Phase 2/4）

- `internal/rule` ACL4SSR ini 解析、`internal/fetch` 订阅拉取（Phase 3）、`internal/server` HTTP 服务

- `testdata/subscription.txt`：23 节点 REALITY 脱敏样本（含 3 个 `29845e28`、1 个 `40452118` 回归用例）

- `testdata/acl_mini.ini` + `testdata/lan.list`：ACL 外配置与规则集测试样本（全远程语义）

