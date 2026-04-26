package similarity

import (
	"math"
	"strings"
	"unicode"
)

var stopwords = map[string]struct{}{
	"the": {}, "is": {}, "at": {}, "which": {}, "on": {},
	"a": {}, "an": {}, "and": {}, "or": {}, "but": {},
	"in": {}, "to": {}, "for": {}, "of": {}, "with": {},
	"as": {}, "by": {}, "this": {}, "that": {}, "it": {},
	"from": {}, "are": {}, "was": {}, "were": {}, "be": {},
	"been": {}, "has": {}, "have": {}, "had": {}, "do": {},
	"does": {}, "did": {}, "will": {}, "would": {}, "could": {},
	"should": {}, "can": {}, "may": {}, "not": {}, "no": {},
	"so": {}, "if": {}, "its": {},
}

// Tokenize lowercases text, splits on non-alphanumeric characters,
// removes stopwords, and filters tokens shorter than 2 characters.
func Tokenize(text string) []string {
	lower := strings.ToLower(text)
	words := strings.FieldsFunc(lower, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})

	tokens := make([]string, 0, len(words))
	for _, w := range words {
		if len(w) < 2 {
			continue
		}
		if _, stop := stopwords[w]; stop {
			continue
		}
		tokens = append(tokens, w)
	}
	return tokens
}

// Corpus holds document frequency counts for TF-IDF computation.
type Corpus struct {
	df       map[string]int
	docCount int
}

// NewCorpus builds a Corpus from a set of documents, computing document
// frequency for each term.
func NewCorpus(documents []string) *Corpus {
	c := &Corpus{
		df:       make(map[string]int),
		docCount: len(documents),
	}

	for _, doc := range documents {
		tokens := Tokenize(doc)
		seen := make(map[string]struct{}, len(tokens))
		for _, t := range tokens {
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			c.df[t]++
		}
	}

	return c
}

// TFIDFVector computes TF-IDF weights for a document against the corpus.
// TF = count(term in doc) / len(doc). IDF = log(N / df(term)).
// Returns a sparse vector as map[string]float64.
func (c *Corpus) TFIDFVector(document string) map[string]float64 {
	tokens := Tokenize(document)
	if len(tokens) == 0 {
		return nil
	}

	tf := make(map[string]int, len(tokens))
	for _, t := range tokens {
		tf[t]++
	}

	docLen := float64(len(tokens))
	n := float64(c.docCount)
	vec := make(map[string]float64, len(tf))

	for term, count := range tf {
		termTF := float64(count) / docLen
		df := c.df[term]
		if df == 0 {
			df = 1
		}
		termIDF := math.Log(n / float64(df))
		weight := termTF * termIDF
		if weight > 0 {
			vec[term] = weight
		}
	}

	return vec
}

// CosineSimilarity computes the cosine similarity between two sparse TF-IDF
// vectors. Returns 0.0 for zero-length vectors.
func CosineSimilarity(a, b map[string]float64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	var dot float64
	for term, wa := range a {
		if wb, ok := b[term]; ok {
			dot += wa * wb
		}
	}

	normA := vectorNorm(a)
	normB := vectorNorm(b)

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return dot / (normA * normB)
}

func vectorNorm(v map[string]float64) float64 {
	var sum float64
	for _, w := range v {
		sum += w * w
	}
	return math.Sqrt(sum)
}
