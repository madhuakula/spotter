package testing

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"gopkg.in/yaml.v3"

	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/validation"
)

// TestResult represents the result of running a single test case
type TestResult struct {
	TestCase    models.RuleTestCase `json:"testCase"`
	Passed      bool                `json:"passed"`
	Expected    bool                `json:"expected"`
	Actual      bool                `json:"actual"`
	Error       string              `json:"error,omitempty"`
	Description string              `json:"description,omitempty"`
}

// TestSuiteResult represents the result of running a complete test suite
type TestSuiteResult struct {
	RuleID      string       `json:"ruleId"`
	RuleName    string       `json:"ruleName"`
	TotalTests  int          `json:"totalTests"`
	PassedTests int          `json:"passedTests"`
	FailedTests int          `json:"failedTests"`
	Results     []TestResult `json:"results"`
	Success     bool         `json:"success"`
}

// RuleTestRunner provides functionality to run tests for SpotterRules
type RuleTestRunner struct {
	env *cel.Env
}

// NewRuleTestRunner creates a new test runner with CEL environment
func NewRuleTestRunner() (*RuleTestRunner, error) {
	// Create CEL environment with Kubernetes object types
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
		// Add common CEL functions
		cel.Lib(&kubernetesLib{}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &RuleTestRunner{env: env}, nil
}

// RunTestSuite runs all test cases for a given rule
func (r *RuleTestRunner) RunTestSuite(rule *models.SpotterRule, testSuite models.RuleTestSuite) (*TestSuiteResult, error) {
	result := &TestSuiteResult{
		RuleID:      rule.GetID(),
		RuleName:    rule.GetTitle(),
		TotalTests:  len(testSuite),
		PassedTests: 0,
		FailedTests: 0,
		Results:     make([]TestResult, 0, len(testSuite)),
		Success:     true,
	}

	// Compile the CEL expression once
	ast, issues := r.env.Compile(rule.Spec.CEL)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", issues.Err())
	}

	program, err := r.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	// Run each test case
	for _, testCase := range testSuite {
		testResult := r.runSingleTest(program, rule, testCase)
		result.Results = append(result.Results, testResult)

		if testResult.Passed {
			result.PassedTests++
		} else {
			result.FailedTests++
			result.Success = false
		}
	}

	return result, nil
}

// runSingleTest runs a single test case against the rule
func (r *RuleTestRunner) runSingleTest(program cel.Program, rule *models.SpotterRule, testCase models.RuleTestCase) TestResult {
	result := TestResult{
		TestCase: testCase,
		Expected: testCase.Pass,
	}

	// Parse the input YAML into a Kubernetes object
	var kubernetesObject map[string]interface{}
	if err := yaml.Unmarshal([]byte(testCase.Input), &kubernetesObject); err != nil {
		result.Error = fmt.Sprintf("failed to parse test input: %v", err)
		result.Passed = false
		return result
	}

	// Prepare CEL evaluation context
	vars := map[string]interface{}{
		"object": kubernetesObject,
	}

	// Evaluate the CEL expression
	val, _, err := program.Eval(vars)
	if err != nil {
		result.Error = fmt.Sprintf("CEL evaluation error: %v", err)
		result.Passed = false
		return result
	}

	// Extract boolean result
	boolVal, ok := val.Value().(bool)
	if !ok {
		result.Error = fmt.Sprintf("CEL expression returned non-boolean value: %T", val.Value())
		result.Passed = false
		return result
	}

	result.Actual = boolVal

	// Determine if test passed
	// If the rule should pass (testCase.Pass = true), then CEL should return false (no violation)
	// If the rule should fail (testCase.Pass = false), then CEL should return true (violation found)
	expectedCELResult := !testCase.Pass
	result.Passed = (boolVal == expectedCELResult)

	if !result.Passed {
		if testCase.Pass {
			result.Description = fmt.Sprintf("Expected test to pass (no violation), but CEL returned %v (violation detected)", boolVal)
		} else {
			result.Description = fmt.Sprintf("Expected test to fail (violation), but CEL returned %v (no violation)", boolVal)
		}
	}

	return result
}

// ValidateRuleWithTests validates a rule and runs its test suite
func (r *RuleTestRunner) ValidateRuleWithTests(rule *models.SpotterRule, testSuite models.RuleTestSuite) (*TestSuiteResult, error) {
	// First validate the rule structure
	validationResult := validation.ValidateSpotterRule(rule)
	if !validationResult.Valid {
		errorMsgs := make([]string, len(validationResult.Errors))
		for i, err := range validationResult.Errors {
			errorMsgs[i] = err.Error()
		}
		return nil, fmt.Errorf("rule validation failed: %s", strings.Join(errorMsgs, "; "))
	}

	// Run the test suite
	return r.RunTestSuite(rule, testSuite)
}

// kubernetesLib provides additional CEL functions for Kubernetes objects
type kubernetesLib struct{}

func (k *kubernetesLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("has_label",
			cel.Overload("has_label_string_string",
				[]*cel.Type{cel.DynType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(hasLabel),
			),
		),
		cel.Function("get_label",
			cel.Overload("get_label_string_string",
				[]*cel.Type{cel.DynType, cel.StringType},
				cel.StringType,
				cel.BinaryBinding(getLabel),
			),
		),
		cel.Function("has_annotation",
			cel.Overload("has_annotation_string_string",
				[]*cel.Type{cel.DynType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(hasAnnotation),
			),
		),
		cel.Function("get_annotation",
			cel.Overload("get_annotation_string_string",
				[]*cel.Type{cel.DynType, cel.StringType},
				cel.StringType,
				cel.BinaryBinding(getAnnotation),
			),
		),
	}
}

func (k *kubernetesLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// hasLabel checks if a Kubernetes object has a specific label
func hasLabel(lhs, rhs ref.Val) ref.Val {
	obj, ok := lhs.Value().(map[string]interface{})
	if !ok {
		return types.False
	}

	labelKey, ok := rhs.Value().(string)
	if !ok {
		return types.False
	}

	metadata, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		return types.False
	}

	labels, ok := metadata["labels"].(map[string]interface{})
	if !ok {
		return types.False
	}

	_, exists := labels[labelKey]
	return types.Bool(exists)
}

// getLabel gets the value of a specific label from a Kubernetes object
func getLabel(lhs, rhs ref.Val) ref.Val {
	obj, ok := lhs.Value().(map[string]interface{})
	if !ok {
		return types.String("")
	}

	labelKey, ok := rhs.Value().(string)
	if !ok {
		return types.String("")
	}

	metadata, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		return types.String("")
	}

	labels, ok := metadata["labels"].(map[string]interface{})
	if !ok {
		return types.String("")
	}

	value, exists := labels[labelKey]
	if !exists {
		return types.String("")
	}

	strValue, ok := value.(string)
	if !ok {
		return types.String("")
	}

	return types.String(strValue)
}

// hasAnnotation checks if a Kubernetes object has a specific annotation
func hasAnnotation(lhs, rhs ref.Val) ref.Val {
	obj, ok := lhs.Value().(map[string]interface{})
	if !ok {
		return types.False
	}

	annotationKey, ok := rhs.Value().(string)
	if !ok {
		return types.False
	}

	metadata, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		return types.False
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return types.False
	}

	_, exists := annotations[annotationKey]
	return types.Bool(exists)
}

// getAnnotation gets the value of a specific annotation from a Kubernetes object
func getAnnotation(lhs, rhs ref.Val) ref.Val {
	obj, ok := lhs.Value().(map[string]interface{})
	if !ok {
		return types.String("")
	}

	annotationKey, ok := rhs.Value().(string)
	if !ok {
		return types.String("")
	}

	metadata, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		return types.String("")
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return types.String("")
	}

	value, exists := annotations[annotationKey]
	if !exists {
		return types.String("")
	}

	strValue, ok := value.(string)
	if !ok {
		return types.String("")
	}

	return types.String(strValue)
}