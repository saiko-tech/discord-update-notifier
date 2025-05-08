package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/blendle/zapdriver"
	"go.uber.org/zap"
)

func main() {
	logger, err := zapdriver.NewProduction()
	if err != nil {
		log.Fatal("error creating logger:", err)
		return
	}
	defer logger.Sync()

	zap.ReplaceGlobals(logger)

	token := os.Getenv("DISCORD_TOKEN")
	if token == "" {
		zap.S().Fatalw("DISCORD_TOKEN environment variable is not set")
	}

	bot, err := NewBot(token)
	if err != nil {
		zap.S().Fatalw("error creating bot", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := bot.Start(ctx); err != nil {
		zap.S().Fatalw("error starting bot", err)
	}
	defer bot.Stop()

	server := NewServer(bot)
	if err := server.Start(); err != nil {
		zap.S().Fatalw("error starting server", err)
	}
	defer server.Stop()

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM)
	<-sc

	zap.S().Info("received shutdown signal")
}
