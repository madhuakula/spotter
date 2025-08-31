package recommendations

import (
	"math"
	"sort"

	"github.com/madhuakula/spotter/pkg/models"
)

type ruleAgg struct {
	RuleID        string
	Severity      models.SeverityLevel
	Category      string
	Count         int
	DistinctKinds map[string]struct{}
	DistinctNS    map[string]struct{}
}

type ScoredRule struct {
	RuleID     string
	Severity   models.SeverityLevel
	Category   string
	Count      int
	Namespaces int
	Kinds      int
	Score      float64
}

func severityWeight(level models.SeverityLevel) float64 {
	switch level {
	case models.SeverityCritical:
		return 8
	case models.SeverityHigh:
		return 5
	case models.SeverityMedium:
		return 3
	default:
		return 1
	}
}

// ScoreScan computes rule-wise scores and overall risk.
func ScoreScan(scan models.ScanResult) (float64, []ScoredRule) {
	aggs := make(map[string]*ruleAgg)
	for _, r := range scan.Results {
		if r.Passed {
			continue
		}
		a := aggs[r.RuleID]
		if a == nil {
			a = &ruleAgg{RuleID: r.RuleID, Severity: r.Severity, Category: r.Category, DistinctKinds: map[string]struct{}{}, DistinctNS: map[string]struct{}{}}
			aggs[r.RuleID] = a
		}
		a.Count++
		if k := getKind(r.Resource); k != "" {
			a.DistinctKinds[k] = struct{}{}
		}
		if ns := getNamespace(r.Resource); ns != "" {
			a.DistinctNS[ns] = struct{}{}
		}
	}

	var scored []ScoredRule
	var total float64
	for _, a := range aggs {
		sev := severityWeight(a.Severity)
		occ := math.Log(1 + float64(a.Count))
		breadth := 0.0
		nsCount := len(a.DistinctNS)
		if nsCount >= 8 {
			breadth += 2
		} else if nsCount >= 3 {
			breadth += 1
		}
		categoryBoost := 0.0
		switch a.Category {
		case "Access Control", "Network & Traffic Security":
			categoryBoost = 1
		}
		s := sev*(1+occ) + breadth + categoryBoost
		scored = append(scored, ScoredRule{
			RuleID:     a.RuleID,
			Severity:   a.Severity,
			Category:   a.Category,
			Count:      a.Count,
			Namespaces: nsCount,
			Kinds:      len(a.DistinctKinds),
			Score:      s,
		})
		total += s
	}

	// Normalize to 0..100 using a soft cap
	risk := 100 * (1 - math.Exp(-total/20))

	sort.Slice(scored, func(i, j int) bool { return scored[i].Score > scored[j].Score })
	return risk, scored
}

func getNamespace(resource map[string]interface{}) string {
	if resource == nil {
		return ""
	}
	if md, ok := resource["metadata"].(map[string]interface{}); ok {
		if ns, ok := md["namespace"].(string); ok {
			return ns
		}
	}
	if ns, ok := resource["namespace"].(string); ok {
		return ns
	}
	return ""
}

func getKind(resource map[string]interface{}) string {
	if resource == nil {
		return ""
	}
	if k, ok := resource["kind"].(string); ok {
		return k
	}
	return ""
}
