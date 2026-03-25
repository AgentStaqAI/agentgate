package analytics

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agentgate/agentgate/config"
	"gopkg.in/yaml.v3"
)

// HandleStats returns aggregated metrics from SQLite.
func HandleStats(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		http.Error(w, "DB not initialized", http.StatusInternalServerError)
		return
	}

	var total, blocked int
	var avgLatency float64

	db.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&total)
	db.QueryRow(`SELECT COUNT(*) FROM requests WHERE status LIKE 'blocked%'`).Scan(&blocked)
	db.QueryRow(`SELECT COALESCE(AVG(latency_ms), 0) FROM requests`).Scan(&avgLatency)

	response := map[string]any{
		"total":       total,
		"blocked":     blocked,
		"avg_latency": avgLatency,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleHeatmap returns aggregate success/failure rates grouped by ToolName.
func HandleHeatmap(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		http.Error(w, "DB not initialized", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query(`
		SELECT 
			server_name,
			tool_name, 
			COUNT(*) as total_calls,
			SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_calls,
			SUM(CASE WHEN status LIKE 'blocked%' THEN 1 ELSE 0 END) as blocked_calls
		FROM requests 
		GROUP BY server_name, tool_name
		ORDER BY total_calls DESC
	`)
	if err != nil {
		http.Error(w, "Failed to query heatmap", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type ToolStats struct {
		ServerName string `json:"server_name"`
		ToolName   string `json:"tool_name"`
		Total      int    `json:"total_calls"`
		Allowed    int    `json:"allowed_calls"`
		Blocked    int    `json:"blocked_calls"`
	}

	var results []ToolStats
	for rows.Next() {
		var stat ToolStats
		rows.Scan(&stat.ServerName, &stat.ToolName, &stat.Total, &stat.Allowed, &stat.Blocked)
		results = append(results, stat)
	}

	if results == nil {
		results = []ToolStats{} // prevent null in JSON
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// HandleHistory returns the last 50 RequestRecords from the DB.
func HandleHistory(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		http.Error(w, "DB not initialized", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query(`
		SELECT id, timestamp, status, server_name, agent_id, tool_name, arguments, reason, latency_ms, COALESCE(jsonrpc_id, ''), COALESCE(input_payload, ''), COALESCE(output_payload, '')
		FROM requests 
		ORDER BY id DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, "Failed to fetch history", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []RequestRecord
	for rows.Next() {
		var rec RequestRecord
		var argsStr string
		err := rows.Scan(&rec.ID, &rec.Timestamp, &rec.Status, &rec.ServerName, &rec.AgentID, &rec.ToolName, &argsStr, &rec.Reason, &rec.LatencyMs, &rec.JSONRPCID, &rec.InputPayload, &rec.OutputPayload)
		if err == nil && argsStr != "" {
			var args map[string]any
			if json.Unmarshal([]byte(argsStr), &args) == nil {
				rec.Arguments = args
			}
		}
		results = append(results, rec)
	}

	if results == nil {
		results = []RequestRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// HandleConfig simply dumps the live YAML loaded Config struct.
func HandleConfig(getConfig func() *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getConfig())
	}
}

// HandleConfigSave receives a JSON payload outlining a single new Server Sandbox.
// It maps the struct, saves it securely back to the active `agentgate.yaml` via gopkg.in/yaml.v3,
// and invokes the dynamically injected `reloadFunc` to hot-swap the internal multiplexer.
func HandleConfigSave(configPath string, reloadFunc func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			MCPServers map[string]struct {
				ClaudeServerConfig
				Policies config.SecurityPolicy `json:"policies"`
			} `json:"mcpServers"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Read the config freshly from disk so we don't clobber comments or concurrent edits.
		data, err := os.ReadFile(configPath)
		if err != nil {
			http.Error(w, "Error reading config file", http.StatusInternalServerError)
			return
		}

		// Use yaml.Node to parse the tree while 100% preserving `# comments` and `indentation`
		var root yaml.Node
		if err := yaml.Unmarshal(data, &root); err != nil {
			http.Error(w, "Error parsing config file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if len(root.Content) > 0 {
			docNode := root.Content[0]
			var mcpServersNode *yaml.Node

			// Scan for "mcp_servers" block in root YAML
			for i := 0; i < len(docNode.Content); i += 2 {
				if docNode.Content[i].Value == "mcp_servers" {
					mcpServersNode = docNode.Content[i+1]
					break
				}
			}

			if mcpServersNode == nil {
				keyMcp := &yaml.Node{Kind: yaml.ScalarNode, Value: "mcp_servers"}
				mcpServersNode = &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{}}
				docNode.Content = append(docNode.Content, keyMcp, mcpServersNode)
			}

			// Natively marshal the newly extracted block mappings inside iteration
			for srvName, srvData := range payload.MCPServers {
				var upstream string
				if srvData.Transport == "http" || strings.HasPrefix(srvData.Command, "http") || srvData.URL != "" {
					upstream = srvData.URL
					if upstream == "" {
						upstream = srvData.Command
					}
					if upstream == "" && len(srvData.Args) > 0 {
						upstream = srvData.Args[0]
					}
				} else {
					upstream = "exec: " + srvData.Command
					if len(srvData.Args) > 0 {
						upstream += " " + strings.Join(srvData.Args, " ")
					}
				}

				newSrvWrap := map[string]config.MCPServer{
					srvName: {
						Upstream: upstream,
						Env:      srvData.Env,
						Policies: srvData.Policies,
					},
				}
				newSrvBytes, _ := yaml.Marshal(&newSrvWrap)

				var newSrvNode yaml.Node
				yaml.Unmarshal(newSrvBytes, &newSrvNode)
				forceBlockStyle(&newSrvNode)

				keyNode := newSrvNode.Content[0].Content[0]
				valNode := newSrvNode.Content[0].Content[1]

				replaced := false
				for i := 0; i < len(mcpServersNode.Content); i += 2 {
					if mcpServersNode.Content[i].Value == srvName {
						mcpServersNode.Content[i+1] = valNode
						replaced = true
						break
					}
				}
				if !replaced {
					mcpServersNode.Content = append(mcpServersNode.Content, keyNode, valNode)
				}
			}
		}

		// Marshal node tree back to bytes
		updatedData, err := yaml.Marshal(&root)
		if err != nil {
			http.Error(w, "Error encoding YAML AST", http.StatusInternalServerError)
			return
		}

		if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
			http.Error(w, "Error saving config file", http.StatusInternalServerError)
			return
		}

		// Execute Hot Reload
		if err := reloadFunc(); err != nil {
			http.Error(w, "Config saved but Hot Reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}
}

// forceBlockStyle recursively sets the YAML node style to block (0) for all
// mapping and sequence nodes, so the written file is human-readable indented
// YAML rather than inline flow style (e.g. {key: val, ...}).
func forceBlockStyle(n *yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		n.Style = 0 // block style
	}
	for _, child := range n.Content {
		forceBlockStyle(child)
	}
}

// HandleDiscover executes an MCP "Hit-and-Run" extraction using bulk JSON strategies.
func HandleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload ClaudeConfigRoot
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	discovered := make(map[string][]MCPTool)
	discoveryErrors := make(map[string]string)

	for serverName, srvCfg := range payload.MCPServers {
		var transport ClientTransport

		if srvCfg.Transport == "http" || strings.HasPrefix(srvCfg.Command, "http") || srvCfg.URL != "" {
			reqURL := srvCfg.URL
			if reqURL == "" {
				reqURL = srvCfg.Command
			}
			transport = &HTTPTransport{URL: reqURL}
		} else {
			transport = &StdioTransport{
				Command: srvCfg.Command,
				Args:    srvCfg.Args,
				Env:     srvCfg.Env,
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel() // Ensure cancel is called for each iteration

		// Execute the stateful discovery strategy protocol
		client := NewMCPClient(transport)
		tools, err := client.Discover(ctx)
		if err != nil {
			discoveryErrors[serverName] = err.Error()
			discovered[serverName] = []MCPTool{} // Ensure an empty slice for errors
		} else {
			discovered[serverName] = tools
		}
	}

	response := struct {
		Discovered map[string][]MCPTool `json:"discovered"`
		Errors     map[string]string    `json:"errors"`
	}{
		Discovered: discovered,
		Errors:     discoveryErrors,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleSSEStream creates a persistent HTTP connection to stream Live RequestRecords.
func HandleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch, cleanup := Subscribe()
	defer cleanup()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Allow CORS if users want to connect an external frontend later
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Write([]byte("event: connected\ndata: {}\n\n"))
	flusher.Flush()

	for {
		select {
		case data := <-ch:
			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
