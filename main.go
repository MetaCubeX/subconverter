// subconverter-go 入口：启动 HTTP 服务。
// 监听端口默认 25600，可用环境变量 PORT 覆盖。
package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"subconv/internal/server"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "25600"
	}
	addr := ":" + port

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.NewHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("subconverter-go %s 监听 %s", server.Version, addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
