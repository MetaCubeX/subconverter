# subconverter-go（Go 重写版）多阶段构建
# builder：CGO_ENABLED=0 静态编译；运行层仅含静态二进制

# ---------- 构建层 ----------
FROM golang:1.25-alpine AS builder

WORKDIR /src

# 先拷依赖清单，利用 Docker 层缓存加速重复构建
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# 静态编译：运行层无任何 C 依赖；-trimpath/-s/-w 去路径信息与调试符号
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/subconv .

# ---------- 运行层 ----------
FROM alpine:3.20

# 时区数据（组名/日志本地化场景）与 CA 证书（https 订阅/规则配置拉取）
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/subconv /subconv

# 外配置（ACL ini）与规则集均在运行时远程拉取，镜像不含 base/ 资产
EXPOSE 25600
ENTRYPOINT ["/subconv"]
