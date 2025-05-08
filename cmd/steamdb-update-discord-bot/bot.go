package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/blendle/zapdriver"
	"github.com/bwmarrin/discordgo"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

const (
	baseURL     = "https://steamdb.info/api/PatchnotesRSS/?appid=%s"
	cachePath   = "data/last_patch_%s.xml"
	configPath  = "data/subscriptions.json"
	httpAddr    = ":8080"
	httpTimeout = 10 * time.Second
	githubURL   = "https://api.github.com/repos/%s/contents/%s"
)

var (
	httpClient = &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
)

type Subscription struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	AppID      string          `json:"app_id,omitempty"`
	Repo       string          `json:"repo,omitempty"`
	Path       string          `json:"path,omitempty"`
	Branch     string          `json:"branch,omitempty"`
	ChannelIDs map[string]bool `json:"channel_ids"`
	LastMod    string          `json:"last_mod,omitempty"`
}

type Config struct {
	Subscriptions map[string]Subscription `json:"subscriptions"`
	mu            sync.RWMutex
}

type Bot struct {
	session   *discordgo.Session
	config    *Config
	fileCache *FileCache
}

type RSS struct {
	Channel struct {
		Items []struct {
			Title string `xml:"title"`
			Link  string `xml:"link"`
		} `xml:"item"`
	} `xml:"channel"`
}

type Update struct {
	Title string
	URL   string
}

// Pure functions - no side effects
func fetchRSS(appID string, lastMod string) ([]byte, string, error) {
	url := fmt.Sprintf(baseURL, appID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("error creating request: %v", err)
	}

	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("error fetching patchnotes: %v", err)
	}
	defer resp.Body.Close()

	// Check for successful response codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusNotModified {
			zap.S().Debugw("no new updates (304)", "app_id", appID)

			return nil, "", nil
		}

		return nil, "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	newLastMod := resp.Header.Get("Last-Modified")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading response body: %v", err)
	}

	return body, newLastMod, nil
}

func parseRSS(data []byte) (RSS, error) {
	var rss RSS
	if err := xml.Unmarshal(data, &rss); err != nil {
		return RSS{}, fmt.Errorf("error parsing RSS: %v", err)
	}

	return rss, nil
}

func extractLatestUpdate(rss RSS) Update {
	if len(rss.Channel.Items) == 0 {
		return Update{Title: "Unknown Patch"}
	}

	return Update{
		Title: rss.Channel.Items[0].Title,
		URL:   rss.Channel.Items[0].Link,
	}
}

func computeHash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func hasChanged(oldHash, newHash [32]byte) bool {
	return !bytes.Equal(oldHash[:], newHash[:])
}

func createEmbed(update Update) *discordgo.MessageEmbed {
	return &discordgo.MessageEmbed{
		Title:       "New Update Detected",
		Description: update.Title,
		URL:         update.URL,
		Color:       0x00ff00,
	}
}

// fetchGitHubContent retrieves content from a GitHub repository
func fetchGitHubContent(repo, path, lastMod string) ([]byte, string, error) {
	url := fmt.Sprintf(githubURL, repo, path)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	// Add authorization if token is available
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Add If-Modified-Since header if lastMod is provided
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("error fetching GitHub content from %q: %v", url, err)
	}
	defer resp.Body.Close()

	// Check for successful response codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusNotModified {
			zap.S().Debugw("no new updates (304)", "repo", repo, "path", path)
			return nil, "", nil
		}

		return nil, "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	newLastMod := resp.Header.Get("Last-Modified")

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading response body: %v", err)
	}

	return content, newLastMod, nil
}

// fetchDefaultBranch retrieves the default branch for a GitHub repository
func fetchDefaultBranch(repo string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s", repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	// Add authorization if token is available
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error fetching repository info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding response: %v", err)
	}

	return result.DefaultBranch, nil
}

// Bot methods with side effects
func NewBot(token string) (*Bot, error) {
	session, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, fmt.Errorf("error creating Discord session: %v", err)
	}

	fileCache := NewFileCache()
	config, err := readConfigFromCache(fileCache)
	if err != nil {
		return nil, fmt.Errorf("error reading config: %v", err)
	}

	bot := &Bot{
		session:   session,
		config:    config,
		fileCache: fileCache,
	}

	session.AddHandler(bot.ready)
	session.AddHandler(bot.interactionCreate)

	return bot, nil
}

func readConfigFromCache(fileCache *FileCache) (*Config, error) {
	data, err := fileCache.Get(configPath)
	if err != nil {
		return &Config{Subscriptions: map[string]Subscription{}}, nil
	}

	var config Config

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}

	updated := false

	for id, sub := range config.Subscriptions {
		if sub.ID == "" {
			delete(config.Subscriptions, id)
			sub.ID = ulid.Make().String()
			config.Subscriptions[sub.ID] = sub
			updated = true
		}
	}

	if updated {
		err := fileCache.Set(configPath, data)
		if err != nil {
			return nil, fmt.Errorf("error saving config: %v", err)
		}
	}

	return &config, nil
}

func (b *Bot) saveConfig() error {
	data, err := json.MarshalIndent(b.config, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling config: %v", err)
	}

	return b.fileCache.Set(configPath, data)
}

func (b *Bot) readCache(appID string) ([]byte, error) {
	path := fmt.Sprintf(cachePath, appID)
	return b.fileCache.Get(path)
}

func (b *Bot) writeCache(appID string, data []byte) error {
	path := fmt.Sprintf(cachePath, appID)
	return b.fileCache.Set(path, data)
}

func (b *Bot) Start(ctx context.Context) error {
	if err := b.session.Open(); err != nil {
		return fmt.Errorf("error opening connection: %v", err)
	}

	if err := b.registerCommands(); err != nil {
		return fmt.Errorf("error registering commands: %v", err)
	}

	go b.checkUpdates(ctx)

	return nil
}

func (b *Bot) Stop() {
	zap.S().Info("shutting down bot")
	b.session.Close()
}

func (b *Bot) ready(s *discordgo.Session, event *discordgo.Ready) {
	zap.S().Infow("bot is ready",
		"username", s.State.User.Username,
		"discriminator", s.State.User.Discriminator,
	)
}

func (b *Bot) registerCommands() error {
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "subscribe-steamdb",
			Description: "Subscribe to Steam game patch notes",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "app_id",
					Description: "Steam App ID (e.g., 730 for CS:GO)",
					Required:    true,
				},
			},
		},
		{
			Name:        "subscribe-github",
			Description: "Subscribe to GitHub content updates",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "repo",
					Description: "GitHub repository (e.g., owner/repo)",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "path",
					Description: "Path to the file or directory in the repository (optional, defaults to repository root)",
					Required:    false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "branch",
					Description: "Branch name (optional, defaults to repository's default branch)",
					Required:    false,
				},
			},
		},
		{
			Name:        "unsubscribe-steamdb",
			Description: "Unsubscribe from Steam game patch notes",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "app_id",
					Description: "Steam App ID to unsubscribe from",
					Required:    true,
				},
			},
		},
		{
			Name:        "unsubscribe-github",
			Description: "Unsubscribe from GitHub content updates",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "repo",
					Description: "GitHub repository (e.g., owner/repo)",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "path",
					Description: "Path to the file or directory in the repository (optional, defaults to repository root)",
					Required:    false,
				},
			},
		},
	}

	_, err := b.session.ApplicationCommandBulkOverwrite(b.session.State.User.ID, "", commands)
	if err != nil {
		return fmt.Errorf("error overwriting commands: %w", err)
	}

	return nil
}

func (b *Bot) interactionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommand {
		return
	}

	var err error
	switch i.ApplicationCommandData().Name {
	case "subscribe-steamdb":
		err = b.handleSubscribeSteamDB(s, i)
	case "subscribe-github":
		err = b.handleSubscribeGitHub(s, i)
	case "unsubscribe-steamdb":
		err = b.handleUnsubscribeSteamDB(s, i)
	case "unsubscribe-github":
		err = b.handleUnsubscribeGitHub(s, i)
	}

	if err != nil {
		zap.S().Errorw("error handling interaction",
			zapdriver.ServiceContext("steamdb-update-notifier"),
			zapdriver.ErrorReport(runtime.Caller(0)),
			"command", i.ApplicationCommandData().Name,
			"error", err,
		)
	}
}

func (b *Bot) handleSubscribeSteamDB(s *discordgo.Session, i *discordgo.InteractionCreate) error {
	options := i.ApplicationCommandData().Options
	channelID := i.ChannelID

	// Get subscription type
	appID := options[0].StringValue()

	zap.S().Infow("handling subscribe request",
		"type", "steamdb",
		"app_id", appID,
		"channel_id", channelID,
	)

	b.config.mu.Lock()
	defer b.config.mu.Unlock()

	// Check if subscription already exists
	for id, sub := range b.config.Subscriptions {
		if sub.Type == "steamdb" && sub.AppID == appID {
			// Check if channel is already subscribed
			for id := range sub.ChannelIDs {
				if id == channelID {
					zap.S().Infow("channel already subscribed",
						"type", "steamdb",
						"app_id", appID,
						"channel_id", channelID,
					)
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: "This channel is already subscribed to this game's updates!",
						},
					})

					return nil
				}
			}

			// Add channel to existing subscription
			sub.ChannelIDs[channelID] = true
			b.config.Subscriptions[id] = sub

			if err := b.saveConfig(); err != nil {
				return fmt.Errorf("error saving config: %v", err)
			}

			zap.S().Infow("successfully subscribed channel",
				"type", "steamdb",
				"app_id", appID,
				"channel_id", channelID,
			)

			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Successfully subscribed to updates for App ID: %s", appID),
				},
			})

			return nil
		}
	}

	// Create new subscription
	newSub := Subscription{
		ID:         ulid.Make().String(),
		Type:       "steamdb",
		AppID:      appID,
		ChannelIDs: map[string]bool{channelID: true},
	}

	b.config.Subscriptions[newSub.ID] = newSub

	if err := b.saveConfig(); err != nil {
		return fmt.Errorf("error saving config: %v", err)
	}

	zap.S().Infow("successfully created new subscription",
		"type", "steamdb",
		"app_id", appID,
		"channel_id", channelID,
	)

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("Successfully subscribed to updates for App ID: %s", appID),
		},
	})

	return nil
}

func (b *Bot) handleSubscribeGitHub(s *discordgo.Session, i *discordgo.InteractionCreate) error {
	options := i.ApplicationCommandData().Options
	channelID := i.ChannelID

	// Get subscription parameters
	repo := options[0].StringValue()
	path := ""
	if len(options) > 1 {
		path = options[1].StringValue()
	}

	// Get branch if provided, otherwise fetch default branch
	var branch string
	if len(options) > 2 && options[2].StringValue() != "" {
		branch = options[2].StringValue()
	} else {
		var err error
		branch, err = fetchDefaultBranch(repo)
		if err != nil {
			return fmt.Errorf("error fetching default branch: %v", err)
		}
	}

	zap.S().Infow("handling subscribe request",
		"type", "github-contents",
		"repo", repo,
		"path", path,
		"branch", branch,
		"channel_id", channelID,
	)

	b.config.mu.Lock()
	defer b.config.mu.Unlock()

	// Check if subscription already exists
	for id, sub := range b.config.Subscriptions {
		if sub.Type == "github-contents" && sub.Repo == repo && sub.Path == path && sub.Branch == branch {
			// Check if channel is already subscribed
			if _, exists := sub.ChannelIDs[channelID]; exists {
				zap.S().Infow("channel already subscribed",
					"type", "github-contents",
					"repo", repo,
					"path", path,
					"branch", branch,
					"channel_id", channelID,
				)
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "This channel is already subscribed to this GitHub content!",
					},
				})

				return nil
			}

			// Add channel to existing subscription
			sub.ChannelIDs[channelID] = true
			b.config.Subscriptions[id] = sub

			if err := b.saveConfig(); err != nil {
				return fmt.Errorf("error saving config: %v", err)
			}

			zap.S().Infow("successfully subscribed channel",
				"type", "github-contents",
				"repo", repo,
				"path", path,
				"branch", branch,
				"channel_id", channelID,
			)

			responseMsg := fmt.Sprintf("Successfully subscribed to updates for GitHub content: %s", repo)
			if path != "" {
				responseMsg += fmt.Sprintf("/%s", path)
			}
			if branch != "" {
				responseMsg += fmt.Sprintf(" (branch: %s)", branch)
			}

			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: responseMsg,
				},
			})

			return nil
		}
	}

	// Create new subscription
	newSub := Subscription{
		ID:         ulid.Make().String(),
		Type:       "github-contents",
		Repo:       repo,
		Path:       path,
		Branch:     branch,
		ChannelIDs: map[string]bool{channelID: true},
	}

	b.config.Subscriptions[newSub.ID] = newSub

	if err := b.saveConfig(); err != nil {
		return fmt.Errorf("error saving config: %v", err)
	}

	zap.S().Infow("successfully created new subscription",
		"type", "github-contents",
		"repo", repo,
		"path", path,
		"branch", branch,
		"channel_id", channelID,
	)

	responseMsg := fmt.Sprintf("Successfully subscribed to updates for GitHub content: %s", repo)
	if path != "" {
		responseMsg += fmt.Sprintf("/%s", path)
	}
	if branch != "" {
		responseMsg += fmt.Sprintf(" (branch: %s)", branch)
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: responseMsg,
		},
	})

	return nil
}

func (b *Bot) handleUnsubscribeSteamDB(s *discordgo.Session, i *discordgo.InteractionCreate) error {
	options := i.ApplicationCommandData().Options
	channelID := i.ChannelID

	// Get subscription type
	appID := options[0].StringValue()

	zap.S().Infow("handling unsubscribe request",
		"type", "steamdb",
		"app_id", appID,
		"channel_id", channelID,
	)

	b.config.mu.Lock()
	defer b.config.mu.Unlock()

	// Find subscription by app ID
	var subID string
	for id, sub := range b.config.Subscriptions {
		if sub.Type == "steamdb" && sub.AppID == appID {
			subID = id
			break
		}
	}

	if subID == "" {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "This channel is not subscribed to this content.",
			},
		})
		return nil
	}

	sub := b.config.Subscriptions[subID]

	// Check if channel exists in subscription
	if _, exists := sub.ChannelIDs[channelID]; exists {
		// Remove channel from subscription
		delete(sub.ChannelIDs, channelID)

		// If no channels left, remove the subscription
		if len(sub.ChannelIDs) == 0 {
			delete(b.config.Subscriptions, subID)
		} else {
			b.config.Subscriptions[subID] = sub
		}

		if err := b.saveConfig(); err != nil {
			return fmt.Errorf("error saving config: %v", err)
		}

		zap.S().Infow("successfully unsubscribed channel",
			"type", "steamdb",
			"app_id", appID,
			"channel_id", channelID,
		)

		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Successfully unsubscribed from updates for App ID: %s", appID),
			},
		})

		return nil
	}

	// Channel not found in subscription
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "This channel is not subscribed to this game's updates.",
		},
	})

	return nil
}

func (b *Bot) handleUnsubscribeGitHub(s *discordgo.Session, i *discordgo.InteractionCreate) error {
	options := i.ApplicationCommandData().Options
	channelID := i.ChannelID

	// Get subscription parameters
	repo := options[0].StringValue()
	path := ""
	if len(options) > 1 {
		path = options[1].StringValue()
	}

	zap.S().Infow("handling unsubscribe request",
		"type", "github-contents",
		"repo", repo,
		"path", path,
		"channel_id", channelID,
	)

	b.config.mu.Lock()
	defer b.config.mu.Unlock()

	// Find subscription by repo and path
	var subID string
	for id, sub := range b.config.Subscriptions {
		if sub.Type == "github-contents" && sub.Repo == repo && sub.Path == path {
			subID = id
			break
		}
	}

	if subID == "" {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "This channel is not subscribed to this content.",
			},
		})
		return nil
	}

	sub := b.config.Subscriptions[subID]

	// Check if channel exists in subscription
	if _, exists := sub.ChannelIDs[channelID]; exists {
		// Remove channel from subscription
		delete(sub.ChannelIDs, channelID)

		// If no channels left, remove the subscription
		if len(sub.ChannelIDs) == 0 {
			delete(b.config.Subscriptions, subID)
		} else {
			b.config.Subscriptions[subID] = sub
		}

		if err := b.saveConfig(); err != nil {
			return fmt.Errorf("error saving config: %v", err)
		}

		zap.S().Infow("successfully unsubscribed channel",
			"type", "github-contents",
			"repo", repo,
			"path", path,
			"channel_id", channelID,
		)

		responseMsg := fmt.Sprintf("Successfully unsubscribed from updates for GitHub content: %s", repo)
		if path != "" {
			responseMsg += fmt.Sprintf("/%s", path)
		}

		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: responseMsg,
			},
		})

		return nil
	}

	// Channel not found in subscription
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "This channel is not subscribed to this GitHub content.",
		},
	})

	return nil
}

func (b *Bot) checkUpdates(ctx context.Context) {
	updateTicker := time.NewTicker(2 * time.Minute)
	defer updateTicker.Stop()

	for {
		b.config.mu.RLock()
		subscriptions := make([]Subscription, 0, len(b.config.Subscriptions))
		for _, sub := range b.config.Subscriptions {
			subscriptions = append(subscriptions, sub)
		}
		b.config.mu.RUnlock()

		zap.S().Infow("checking updates",
			"subscription_count", len(subscriptions),
		)

		for _, sub := range subscriptions {
			var err error

			switch sub.Type {
			case "steamdb":
				err = b.checkGameUpdates(sub)
			case "github-contents":
				err = b.checkGitHubUpdates(sub)
			default:
				zap.S().Warnw("unknown subscription type",
					"type", sub.Type,
				)
				continue
			}

			if err != nil {
				zap.S().Errorw("error checking updates",
					zapdriver.ServiceContext("steamdb-update-notifier"),
					zapdriver.ErrorReport(runtime.Caller(0)),
					"type", sub.Type,
					"error", err,
				)
			}
		}

		if err := b.saveConfig(); err != nil {
			zap.S().Errorw("error saving config",
				zapdriver.ServiceContext("steamdb-update-notifier"),
				zapdriver.ErrorReport(runtime.Caller(0)),
				"error", err,
			)
		}

		select {
		case <-ctx.Done():
			return
		case <-updateTicker.C:
		}
	}
}

func (b *Bot) checkGameUpdates(sub Subscription) error {
	zap.S().Debugw("checking game updates",
		"app_id", sub.AppID,
		"channel_count", len(sub.ChannelIDs),
	)

	// Fetch RSS data
	newData, newLastMod, err := fetchRSS(sub.AppID, sub.LastMod)
	if err != nil {
		return fmt.Errorf("error fetching RSS: %v", err)
	}

	if newData == nil {
		zap.S().Debugw("no new updates", "app_id", sub.AppID)
		return nil
	}

	// Update last modified time in config if it changed
	if newLastMod != "" && newLastMod != sub.LastMod {
		b.config.mu.Lock()
		if s, exists := b.config.Subscriptions[sub.ID]; exists {
			s.LastMod = newLastMod
			b.config.Subscriptions[sub.ID] = s
		}
		b.config.mu.Unlock()
	}

	// Check if content has changed
	oldData, err := b.readCache(sub.AppID)
	if err == nil {
		oldHash := computeHash(oldData)
		newHash := computeHash(newData)
		if !hasChanged(oldHash, newHash) {
			zap.S().Debugw("content unchanged",
				"app_id", sub.AppID,
			)
			return nil
		}
	}

	// Parse and extract update
	rss, err := parseRSS(newData)
	if err != nil {
		return fmt.Errorf("error parsing RSS: %v", err)
	}

	update := extractLatestUpdate(rss)
	zap.S().Infow("new update detected",
		"app_id", sub.AppID,
		"title", update.Title,
	)

	// Save to cache
	if err := b.writeCache(sub.AppID, newData); err != nil {
		return fmt.Errorf("error saving cache: %v", err)
	}

	// Send update to channels
	embed := createEmbed(update)
	for id := range sub.ChannelIDs {
		_, err := b.session.ChannelMessageSendEmbed(id, embed)
		if err != nil {
			return fmt.Errorf("error sending message to channel %s: %v", id, err)
		}
	}

	return nil
}

// checkGitHubUpdates checks for updates to GitHub content
func (b *Bot) checkGitHubUpdates(sub Subscription) error {
	zap.S().Debugw("checking GitHub content updates",
		"repo", sub.Repo,
		"path", sub.Path,
		"channel_count", len(sub.ChannelIDs),
	)

	// Fetch GitHub content
	newData, newLastMod, err := fetchGitHubContent(sub.Repo, sub.Path, sub.LastMod)
	if err != nil {
		return fmt.Errorf("error fetching GitHub content from %s %s: %v", sub.Repo, sub.Path, err)
	}

	if newData == nil {
		zap.S().Debugw("no new updates", "repo", sub.Repo, "path", sub.Path)
		return nil
	}

	// Update last modified time in config if it changed
	if newLastMod != "" && newLastMod != sub.LastMod {
		b.config.mu.Lock()
		if s, exists := b.config.Subscriptions[sub.ID]; exists {
			s.LastMod = newLastMod
			b.config.Subscriptions[sub.ID] = s
		}
		b.config.mu.Unlock()
	}

	// Check if content has changed
	cacheKey := fmt.Sprintf("%s_%s", strings.ReplaceAll(sub.Repo, "/", "_"), strings.ReplaceAll(sub.Path, "/", "_"))
	oldData, err := b.readCache(cacheKey)
	if err == nil {
		oldHash := computeHash(oldData)
		newHash := computeHash(newData)
		if !hasChanged(oldHash, newHash) {
			zap.S().Debugw("content unchanged",
				"repo", sub.Repo,
				"path", sub.Path,
			)
			return nil
		}
	}

	var url string
	if newData[0] == '[' {
		url = fmt.Sprintf("https://github.com/%s/tree/%s/%s", sub.Repo, sub.Branch, sub.Path)
	} else {
		url = fmt.Sprintf("https://github.com/%s/blob/%s/%s", sub.Repo, sub.Branch, sub.Path)
	}

	// Create update notification
	update := Update{
		Title: fmt.Sprintf("GitHub content updated: %s/%s (branch: %s)", sub.Repo, sub.Path, sub.Branch),
		URL:   url,
	}

	zap.S().Infow("new GitHub content update detected",
		"repo", sub.Repo,
		"path", sub.Path,
		"branch", sub.Branch,
	)

	// Save to cache
	if err := b.writeCache(cacheKey, newData); err != nil {
		return fmt.Errorf("error saving cache: %v", err)
	}

	// Send update to channels
	embed := createEmbed(update)
	for id := range sub.ChannelIDs {
		_, err := b.session.ChannelMessageSendEmbed(id, embed)
		if err != nil {
			return fmt.Errorf("error sending message to channel %s: %v", id, err)
		}
	}

	return nil
}
