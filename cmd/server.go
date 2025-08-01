package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/madhuakula/spotter/pkg/engine"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/parser"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run Spotter as admission controller server",
	Long: `Run Spotter as a Kubernetes admission controller server.

This command starts an HTTPS server that acts as a ValidatingAdmissionWebhook
to scan resources as they are created/updated in the cluster and either 
allow, deny, or evaluate them based on security rules.

The server uses embedded built-in security rules and provides health check
endpoints for monitoring.

Examples:
  # Run as validating admission controller
  spotter server --mode=validating --port=8443
  
  # Run as evaluating controller (logs violations but allows resources)
  spotter server --mode=evaluating --port=8443 --namespaces=default,production
  
  # Run with TLS certificates
  spotter server --tls-cert-file=server.crt --tls-key-file=server.key`,
	RunE: runServer,
}

// ServerConfig holds the server configuration
type ServerConfig struct {
	Mode          string // "validating" or "evaluating"
	Port          int
	TLSCertFile   string
	TLSKeyFile    string
	Namespaces    []string
	ResourceTypes []string
	MinSeverity   string
	LogFormat     string
	LogLevel      string
}

// Removed unused variables scheme and codecs

func init() {
	rootCmd.AddCommand(serverCmd)

	// Server configuration flags
	serverCmd.Flags().String("mode", "validating", "server mode: 'validating' (block violations) or 'evaluating' (log violations)")
	serverCmd.Flags().Int("port", 8443, "HTTPS server port")
	serverCmd.Flags().String("tls-cert-file", "/etc/certs/tls.crt", "TLS certificate file path")
	serverCmd.Flags().String("tls-key-file", "/etc/certs/tls.key", "TLS private key file path")
	serverCmd.Flags().StringSlice("namespaces", []string{}, "namespaces to monitor (empty = all namespaces)")
	serverCmd.Flags().StringSlice("resource-types", []string{}, "resource types to monitor (empty = all supported types)")
	serverCmd.Flags().String("min-severity", "medium", "minimum severity level to act upon (low, medium, high, critical)")

	// Bind flags to viper
	if err := viper.BindPFlag("server.mode", serverCmd.Flags().Lookup("mode")); err != nil {
		panic(fmt.Sprintf("failed to bind server.mode flag: %v", err))
	}
	if err := viper.BindPFlag("server.port", serverCmd.Flags().Lookup("port")); err != nil {
		panic(fmt.Sprintf("failed to bind server.port flag: %v", err))
	}
	if err := viper.BindPFlag("server.tls-cert-file", serverCmd.Flags().Lookup("tls-cert-file")); err != nil {
		panic(fmt.Sprintf("failed to bind server.tls-cert-file flag: %v", err))
	}
	if err := viper.BindPFlag("server.tls-key-file", serverCmd.Flags().Lookup("tls-key-file")); err != nil {
		panic(fmt.Sprintf("failed to bind server.tls-key-file flag: %v", err))
	}
	if err := viper.BindPFlag("server.namespaces", serverCmd.Flags().Lookup("namespaces")); err != nil {
		panic(fmt.Sprintf("failed to bind server.namespaces flag: %v", err))
	}
	if err := viper.BindPFlag("server.resource-types", serverCmd.Flags().Lookup("resource-types")); err != nil {
		panic(fmt.Sprintf("failed to bind server.resource-types flag: %v", err))
	}
	if err := viper.BindPFlag("server.min-severity", serverCmd.Flags().Lookup("min-severity")); err != nil {
		panic(fmt.Sprintf("failed to bind server.min-severity flag: %v", err))
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	logger := GetLogger()

	// Build server configuration
	config, err := buildServerConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to build server configuration: %w", err)
	}

	logger.Info("Starting Spotter admission controller server",
		"mode", config.Mode,
		"port", config.Port,
		"namespaces", config.Namespaces,
		"min_severity", config.MinSeverity)

	// Load built-in security rules
	rules, err := loadBuiltinSecurityRules()
	if err != nil {
		return fmt.Errorf("failed to load security rules: %w", err)
	}

	logger.Info("Loaded security rules", "count", len(rules))

	// Initialize evaluation engine
	evalEngine, err := engine.NewCELEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize evaluation engine: %w", err)
	}

	// Create admission server
	server := &AdmissionServer{
		Config: config,
		Rules:  rules,
		Engine: evalEngine,
		Logger: logger,
	}

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.healthzHandler)
	mux.HandleFunc("/readyz", server.readyzHandler)
	mux.HandleFunc("/admit", server.admitHandler)
	mux.HandleFunc("/metrics", server.metricsHandler)

	// Configure TLS
	tlsConfig, err := loadTLSConfig(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS configuration: %w", err)
	}

	// Create HTTPS server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("Server listening", "port", config.Port)
		serverErrors <- httpServer.ListenAndServeTLS("", "")
	}()

	// Wait for interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)
	case sig := <-interrupt:
		logger.Info("Received shutdown signal", "signal", sig)

		// Graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("Server shutdown error", "error", err)
			return err
		}

		logger.Info("Server shut down gracefully")
	}

	return nil
}

// AdmissionServer handles admission webhook requests
type AdmissionServer struct {
	Config *ServerConfig
	Rules  []*models.SecurityRule
	Engine engine.EvaluationEngine
	Logger interface {
		Info(string, ...interface{})
		Error(string, ...interface{})
	}
}

// admitHandler handles admission webhook requests
func (s *AdmissionServer) admitHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Log request
	s.Logger.Info("Received admission request",
		"method", r.Method,
		"url", r.URL.Path,
		"remote_addr", r.RemoteAddr)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.Logger.Error("Failed to read request body", "error", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	// Decode admission review
	var admissionReview admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReview); err != nil {
		s.Logger.Error("Failed to decode admission review", "error", err)
		http.Error(w, "Failed to decode request", http.StatusBadRequest)
		return
	}

	// Process admission request
	response := s.processAdmissionRequest(admissionReview.Request)

	// Build response
	admissionResponse := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: response,
	}

	// Encode response
	responseBytes, err := json.Marshal(admissionResponse)
	if err != nil {
		s.Logger.Error("Failed to encode admission response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(responseBytes); err != nil {
		s.Logger.Error("Failed to write response", "error", err)
	}

	// Log response
	duration := time.Since(start)
	s.Logger.Info("Completed admission request",
		"allowed", response.Allowed,
		"duration", duration,
		"uid", response.UID)
}

// processAdmissionRequest evaluates the resource against security rules
func (s *AdmissionServer) processAdmissionRequest(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	// Check if we should process this resource
	if !s.shouldProcessResource(req) {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
			Result:  &metav1.Status{Message: "Resource not in scope"},
		}
	}

	// Extract resource object
	var resource map[string]interface{}
	if err := json.Unmarshal(req.Object.Raw, &resource); err != nil {
		s.Logger.Error("Failed to unmarshal resource object", "error", err)
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: "Failed to parse resource"},
		}
	}

	// Log resource being evaluated
	s.Logger.Info("Evaluating resource",
		"kind", req.Kind.Kind,
		"namespace", req.Namespace,
		"name", req.Name,
		"operation", req.Operation)

	// Evaluate rules against resource
	ctx := context.Background()
	result, err := s.Engine.EvaluateRulesAgainstResources(ctx, s.Rules, []map[string]interface{}{resource})
	if err != nil {
		s.Logger.Error("Failed to evaluate resource", "error", err)
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: "Evaluation failed"},
		}
	}

	// Filter results by severity
	violations := s.filterViolationsBySeverity(result.Results)

	// Process results based on mode
	if len(violations) == 0 {
		s.Logger.Info("Resource passed security evaluation",
			"kind", req.Kind.Kind,
			"namespace", req.Namespace,
			"name", req.Name)

		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
			Result:  &metav1.Status{Message: "Security evaluation passed"},
		}
	}

	// Log violations
	s.logViolations(req, violations)

	// Handle violations based on mode
	switch s.Config.Mode {
	case "validating":
		// Block the resource
		message := s.buildViolationMessage(violations)
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result: &metav1.Status{
				Code:    http.StatusForbidden,
				Message: message,
			},
		}
	case "evaluating":
		// Allow but log violations
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
			Result:  &metav1.Status{Message: "Security violations logged"},
		}
	default:
		s.Logger.Error("Unknown server mode", "mode", s.Config.Mode)
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: "Server misconfigured"},
		}
	}
}

// shouldProcessResource checks if the resource should be processed
func (s *AdmissionServer) shouldProcessResource(req *admissionv1.AdmissionRequest) bool {
	// Check namespace filter
	if len(s.Config.Namespaces) > 0 {
		namespaceInScope := false
		for _, ns := range s.Config.Namespaces {
			if req.Namespace == ns {
				namespaceInScope = true
				break
			}
		}
		if !namespaceInScope {
			return false
		}
	}

	// Check resource type filter
	if len(s.Config.ResourceTypes) > 0 {
		resourceKind := req.Kind.Kind
		resourceInScope := false
		for _, rt := range s.Config.ResourceTypes {
			if resourceKind == rt {
				resourceInScope = true
				break
			}
		}
		if !resourceInScope {
			return false
		}
	}

	return true
}

// filterViolationsBySeverity filters violations by minimum severity
func (s *AdmissionServer) filterViolationsBySeverity(results []models.ValidationResult) []models.ValidationResult {
	severityLevels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	minLevel := severityLevels[s.Config.MinSeverity]
	var violations []models.ValidationResult

	for _, result := range results {
		if !result.Passed {
			resultLevel := severityLevels[string(result.Severity)]
			if resultLevel >= minLevel {
				violations = append(violations, result)
			}
		}
	}

	return violations
}

// logViolations logs security violations summary
func (s *AdmissionServer) logViolations(req *admissionv1.AdmissionRequest, violations []models.ValidationResult) {
	if len(violations) == 0 {
		return
	}

	// Count violations by severity
	severityCount := make(map[string]int)
	criticalViolations := []models.ValidationResult{}

	for _, violation := range violations {
		severityStr := string(violation.Severity)
		severityCount[severityStr]++
		if violation.Severity == models.SeverityCritical {
			criticalViolations = append(criticalViolations, violation)
		}
	}

	// Log summary
	s.Logger.Error("Security violations detected",
		"kind", req.Kind.Kind,
		"namespace", req.Namespace,
		"name", req.Name,
		"total_violations", len(violations),
		"critical", severityCount["CRITICAL"],
		"high", severityCount["HIGH"],
		"medium", severityCount["MEDIUM"],
		"low", severityCount["LOW"])

	// Log critical violations with details
	for _, violation := range criticalViolations {
		s.Logger.Error("Critical security violation",
			"rule_id", violation.RuleID,
			"message", violation.Message,
			"category", violation.Category)
	}
}

// buildViolationMessage builds a human-readable violation message
func (s *AdmissionServer) buildViolationMessage(violations []models.ValidationResult) string {
	if len(violations) == 1 {
		return fmt.Sprintf("Security violation: %s (Rule: %s, Severity: %s)",
			violations[0].Message, violations[0].RuleID, violations[0].Severity)
	}

	return fmt.Sprintf("Multiple security violations detected (%d total). First: %s (Rule: %s, Severity: %s)",
		len(violations), violations[0].Message, violations[0].RuleID, violations[0].Severity)
}

// healthzHandler handles health check requests
func (s *AdmissionServer) healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		s.Logger.Error("Failed to write health check response", "error", err)
	}
}

// readyzHandler handles readiness check requests
func (s *AdmissionServer) readyzHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Add more sophisticated readiness checks
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Ready")); err != nil {
		s.Logger.Error("Failed to write readiness check response", "error", err)
	}
}

// metricsHandler handles metrics requests
func (s *AdmissionServer) metricsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Add Prometheus metrics
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("# Metrics endpoint - TODO: implement Prometheus metrics\n")); err != nil {
		s.Logger.Error("Failed to write metrics response", "error", err)
	}
}

// buildServerConfig creates server configuration from command flags
func buildServerConfig(cmd *cobra.Command) (*ServerConfig, error) {
	config := &ServerConfig{
		Mode:        viper.GetString("server.mode"),
		Port:        viper.GetInt("server.port"),
		TLSCertFile: viper.GetString("server.tls-cert-file"),
		TLSKeyFile:  viper.GetString("server.tls-key-file"),
		MinSeverity: viper.GetString("server.min-severity"),
		LogFormat:   viper.GetString("log-format"),
		LogLevel:    viper.GetString("log-level"),
	}

	if cmd.Flags().Changed("namespaces") {
		config.Namespaces, _ = cmd.Flags().GetStringSlice("namespaces")
	}

	if cmd.Flags().Changed("resource-types") {
		config.ResourceTypes, _ = cmd.Flags().GetStringSlice("resource-types")
	}

	// Validate mode
	if config.Mode != "validating" && config.Mode != "evaluating" {
		return nil, fmt.Errorf("invalid mode: %s (must be 'validating' or 'evaluating')", config.Mode)
	}

	// Validate severity
	validSeverities := []string{"low", "medium", "high", "critical"}
	validSeverity := false
	for _, severity := range validSeverities {
		if config.MinSeverity == severity {
			validSeverity = true
			break
		}
	}
	if !validSeverity {
		return nil, fmt.Errorf("invalid min-severity: %s (must be one of: %v)", config.MinSeverity, validSeverities)
	}

	return config, nil
}

// loadTLSConfig loads TLS configuration
func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// loadBuiltinSecurityRules loads only the built-in embedded security rules
func loadBuiltinSecurityRules() ([]*models.SecurityRule, error) {
	if BuiltinRulesFS == nil {
		return nil, fmt.Errorf("built-in rules filesystem not initialized")
	}

	parser := parser.NewYAMLParser(true)
	rules, err := parser.ParseRulesFromFS(context.Background(), BuiltinRulesFS, "internal/builtin")
	if err != nil {
		return nil, fmt.Errorf("failed to parse built-in rules: %w", err)
	}

	return rules, nil
}
