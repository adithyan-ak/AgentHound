package riskscore

import (
	"math"
	"sort"
)

// Assessment keeps the legacy rankable score while disclosing uncertainty.
// Score is conservative (the upper bound) whenever an input is unknown.
type Assessment struct {
	Score          float64
	Min            float64
	Max            float64
	Complete       bool
	UnknownFactors []string
}

type weightedAssessment struct {
	weight float64
	value  Assessment
}

func exactAssessment(score float64) Assessment {
	score = roundRisk(score)
	return Assessment{Score: score, Min: score, Max: score, Complete: true}
}

func ExactAssessment(score float64) Assessment {
	return exactAssessment(score)
}

func unknownAssessment(factor string, min, max float64) Assessment {
	return Assessment{
		Score:          roundRisk(max),
		Min:            roundRisk(min),
		Max:            roundRisk(max),
		Complete:       false,
		UnknownFactors: []string{factor},
	}
}

func combineAssessments(parts ...weightedAssessment) Assessment {
	result := Assessment{Complete: true}
	unknown := make(map[string]bool)
	for _, part := range parts {
		result.Score += part.weight * part.value.Score
		result.Min += part.weight * part.value.Min
		result.Max += part.weight * part.value.Max
		if !part.value.Complete {
			result.Complete = false
		}
		for _, factor := range part.value.UnknownFactors {
			unknown[factor] = true
		}
	}
	result.Score = roundRisk(result.Score)
	result.Min = roundRisk(result.Min)
	result.Max = roundRisk(result.Max)
	for factor := range unknown {
		result.UnknownFactors = append(result.UnknownFactors, factor)
	}
	sort.Strings(result.UnknownFactors)
	return result
}

func roundRisk(score float64) float64 {
	return math.Round(score*100) / 100
}
