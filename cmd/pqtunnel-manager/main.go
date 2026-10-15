package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminui"
	"github.com/hatinati2/PQTunnel/internal/manager"
	"github.com/hatinati2/PQTunnel/internal/speedtest"
)

func main() {
	roleText := os.Getenv("PQTUNNEL_MANAGER_ROLE")
	role := manager.Role(roleText)
	if role != manager.RoleGateway && role != manager.RoleDialer {
		fatalIf(fmt.Errorf("PQTUNNEL_MANAGER_ROLE must be gateway or dialer"))
	}
	listen := envString("PQTUNNEL_MANAGER_LISTEN", "127.0.0.1:9091")
	fatalIf(adminui.ValidateLoopbackAddress(listen))
	token := os.Getenv("PQTUNNEL_MANAGER_TOKEN")
	if len([]byte(token)) < 32 {
		fatalIf(fmt.Errorf("PQTUNNEL_MANAGER_TOKEN must contain at least 32 bytes"))
	}
	controller, err := manager.New(manager.Options{
		Role: role,
		ConfigPath: manager.ConfigPathForRole(role),
		BackupDir: "/var/lib/pqtunnel-manager/backups",
		IPCSocket: "/run/pqtunnel/control.sock",
		SpeedTestPeer: os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_PEER"),
		SpeedTestToken: os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_TOKEN"),
	})
	fatalIf(err)
	handler, err := adminui.New(token, controller)
	fatalIf(err)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agentListen := os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_LISTEN")
	agentToken := os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_TOKEN")
	if agentListen != "" || agentToken != "" {
		if agentListen == "" || len([]byte(agentToken)) < 32 {
			fatalIf(fmt.Errorf("set both PQTUNNEL_MANAGER_SPEEDTEST_LISTEN and a speed-test token of at least 32 bytes"))
		}
		fatalIf(controller.ValidateSpeedTestListener(agentListen, agentToken))
		go func() {
			if err := speedtest.ServeAgent(ctx, agentListen, agentToken); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "pqtunnel-manager: speed-test agent:", err)
			}
		}()
	}
	listener, err := net.Listen("tcp", listen)
	fatalIf(err)
	server := &http.Server{
		Addr: listen, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second,
		WriteTimeout: 310 * time.Second,
		IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 8 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	fmt.Printf("PQTunnel manager (%s) available at http://%s/ (loopback-only; token protected)\n", role, listen)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalIf(err)
	}
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqtunnel-manager:", err)
		os.Exit(1)
	}
}
