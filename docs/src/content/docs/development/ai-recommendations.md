## Post-scan AI Recommendations (Minimal)

**Goal**: Produce top-N, high-impact security recommendations from Spotter scan results using a local LLM (Ollama). Minimal features, pluggable model, deterministic fallback, and unit-tested.

### What it does
- Scores failed findings per rule to compute an overall risk score.
- Selects Top-N rule types contributing most to risk.
- Augments each with short rule blurbs (description/remediation) from built-in rules (exact-match RAG).
- Calls a local LLM to synthesize prioritized, actionable recommendations.
- Falls back to deterministic recommendations when the LLM is unavailable or returns invalid JSON.

### Public API
```go
out, err := recommendations.GenerateRecommendations(ctx, scan, recommendations.Params{
    TopN: 5,
    Model: "llama3.1:8b",       // any Ollama model name
    Host:  "http://localhost:11434",
    Timeout: 8 * time.Second,
})
```

`out.Recommendations` is a list of `{id,title,priority,rationale,actions,related_rules}` and `out.RiskScore` is a 0–100 score.

### Risk scoring (deterministic)
- `severityWeight`: CRITICAL=8, HIGH=5, MEDIUM=3, LOW=1
- `occurrence`: ln(1 + count)
- `breadth`: +1 if >=3 namespaces, +2 if >=8 namespaces
- `categoryBoost`: +1 for Access Control or Network & Traffic Security
- Per-rule: `score = severityWeight * (1 + occurrence) + breadth + categoryBoost`
- Cluster risk: `100 * (1 - exp(-sum(scores)/20))`

### Minimal RAG grounding
- Exact match by `ruleId` against built-in rules (embedded FS).
- Short fields used: `name`, `description`, `remediation`.
- Truncated to keep prompts small.

### LLM call
- Endpoint: `POST {Host}/api/generate`
- Body: `{ model, prompt, stream: false, format: "json", options: { temperature: 0.2 } }`
- Prompt enforces strict JSON: `{ "recommendations": [ ... ] }`.

### Fallback
- If the LLM errors or returns invalid JSON, create deterministic recommendations from Top-N rules using rule blurbs.

### Plug-and-play models
- Pass any model name (e.g., `llama3.1:8b`, `qwen2.5:7b`, `mistral:7b-instruct`).
- No model-specific logic.

### Testing
- Unit tests cover: scoring, RAG loading, prompt build, client success/error, and generator fallback.
- The client tests stub an HTTP server; no external dependency required.

### Notes
- This is intentionally minimal. Later integration points: add CLI flags and reporter wiring if desired.


