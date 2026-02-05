// ZAP Go Client Example
//
// This example demonstrates connecting to a ZAP gateway and using
// the MCP operations: tools, resources, and prompts.
//
// Run with: go run examples/go/main.go

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/zap-proto/zap"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "gateway":
			gatewayExample()
		case "typed":
			typedToolExample()
		default:
			mainExample()
		}
	} else {
		mainExample()
	}
}

func mainExample() {
	fmt.Println("ZAP Chat Client Example (Go)")
	fmt.Println("============================\n")

	ctx := context.Background()

	// Connect to the ZAP gateway
	client, err := zap.Connect(ctx, "zap://localhost:9999")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	fmt.Println("Connected to ZAP gateway\n")

	// Initialize the connection
	serverInfo, err := client.Init(ctx)
	if err != nil {
		log.Fatalf("Failed to init: %v", err)
	}
	fmt.Printf("Server: %s v%s\n", serverInfo.Name, serverInfo.Version)
	fmt.Printf("Protocol: %s\n\n", serverInfo.ProtocolVersion)

	// List available tools
	fmt.Println("Available Tools:")
	fmt.Println("----------------")
	tools, err := client.ListTools(ctx)
	if err != nil {
		log.Fatalf("Failed to list tools: %v", err)
	}
	for _, tool := range tools {
		fmt.Printf("  %s - %s\n", tool.Name, tool.Description)
	}
	fmt.Println()

	// Call a tool
	fmt.Println("Calling 'search' tool...")
	result, err := client.CallTool(ctx, "search", map[string]any{
		"query": "go programming",
		"limit": 5,
	})
	if err != nil {
		log.Fatalf("Failed to call tool: %v", err)
	}

	if result.IsError {
		fmt.Printf("Tool error: %s\n", result.Error)
	} else {
		fmt.Println("Search results:")
		for _, content := range result.Content {
			fmt.Printf("  - %s\n", content.Text)
		}
	}
	fmt.Println()

	// List resources
	fmt.Println("Available Resources:")
	fmt.Println("--------------------")
	resources, err := client.ListResources(ctx)
	if err != nil {
		log.Fatalf("Failed to list resources: %v", err)
	}
	for _, resource := range resources {
		fmt.Printf("  %s - %s\n", resource.URI, resource.Name)
	}
	fmt.Println()

	// Read a resource
	fmt.Println("Reading config resource...")
	content, err := client.ReadResource(ctx, "file:///etc/zap/config.json")
	if err != nil {
		log.Fatalf("Failed to read resource: %v", err)
	}
	fmt.Printf("Config: %s\n\n", content.Text)

	// List prompts
	fmt.Println("Available Prompts:")
	fmt.Println("------------------")
	prompts, err := client.ListPrompts(ctx)
	if err != nil {
		log.Fatalf("Failed to list prompts: %v", err)
	}
	for _, prompt := range prompts {
		desc := prompt.Description
		if desc == "" {
			desc = "(no description)"
		}
		fmt.Printf("  %s - %s\n", prompt.Name, desc)
	}
	fmt.Println()

	// Get a prompt
	fmt.Println("Getting 'code-review' prompt...")
	messages, err := client.GetPrompt(ctx, "code-review", map[string]any{
		"language": "go",
		"file":     "main.go",
	})
	if err != nil {
		log.Fatalf("Failed to get prompt: %v", err)
	}

	fmt.Println("Prompt messages:")
	for _, msg := range messages {
		preview := msg.Content
		if len(preview) > 50 {
			preview = preview[:50]
		}
		fmt.Printf("  [%s] %s...\n", msg.Role, preview)
	}

	fmt.Println("\nDone!")
}

// gatewayExample demonstrates running a ZAP gateway.
func gatewayExample() {
	fmt.Println("Starting ZAP Gateway...")

	ctx := context.Background()

	gateway := zap.NewGateway(zap.GatewayConfig{
		Host: "0.0.0.0",
		Port: 9999,
	})

	// Add MCP servers
	gateway.AddServer("filesystem", "stdio://npx @modelcontextprotocol/server-filesystem /data")
	gateway.AddServer("database", "http://localhost:8080/mcp")
	gateway.AddServer("search", "ws://localhost:9000/ws")

	fmt.Println("Gateway configured with 3 MCP servers")
	fmt.Println("Starting on port 9999...")

	if err := gateway.Start(ctx); err != nil {
		log.Fatalf("Gateway failed: %v", err)
	}
}

// typedToolExample demonstrates using typed tool calls.
func typedToolExample() {
	ctx := context.Background()

	client, err := zap.Connect(ctx, "zap://localhost:9999")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Define typed input
	type SearchInput struct {
		Query   string `json:"query"`
		Limit   int    `json:"limit,omitempty"`
		Filters struct {
			Category  string `json:"category,omitempty"`
			DateRange struct {
				Start string `json:"start"`
				End   string `json:"end"`
			} `json:"dateRange,omitempty"`
		} `json:"filters,omitempty"`
	}

	// Define typed output
	type SearchResult struct {
		ID      string  `json:"id"`
		Title   string  `json:"title"`
		Snippet string  `json:"snippet"`
		Score   float64 `json:"score"`
	}

	// Create typed input
	input := SearchInput{
		Query: "machine learning",
		Limit: 10,
	}
	input.Filters.Category = "articles"
	input.Filters.DateRange.Start = "2024-01-01"
	input.Filters.DateRange.End = "2024-12-31"

	// Call with typed input
	result, err := client.CallTool(ctx, "search", input)
	if err != nil {
		log.Fatalf("Failed to call tool: %v", err)
	}

	// Parse typed response
	for _, content := range result.Content {
		var searchResult SearchResult
		if err := json.Unmarshal([]byte(content.Text), &searchResult); err != nil {
			log.Printf("Failed to parse result: %v", err)
			continue
		}
		fmt.Printf("[%.2f] %s\n", searchResult.Score, searchResult.Title)
		fmt.Printf("  %s\n\n", searchResult.Snippet)
	}
}

// Additional examples for crypto, identity, and consensus would follow
// the same patterns as shown in the Rust and Python examples.
