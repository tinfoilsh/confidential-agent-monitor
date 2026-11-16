package facts

import "slices"

// Vocabulary describes the labels and effects a host accepts. It has no built-in defaults.
// Hosts keep it immutable after supplying it to parsers and policy.
type Vocabulary struct {
	Audiences []string               `json:"audiences"`
	Trusts    []string               `json:"trusts"`
	Effects   map[string]Obligations `json:"effects"`
	Initial   Label                  `json:"initial"`
}

func (v Vocabulary) ValidLabel(l Label) bool {
	return slices.Contains(v.Audiences, l.Audience) && slices.Contains(v.Trusts, l.Trust)
}

func (v Vocabulary) ValidSends(sends string) bool {
	return sends == "" || sends == SendsConnection || slices.Contains(v.Audiences, sends)
}

func (v Vocabulary) ValidEffects(effects []string) bool {
	if len(effects) == 0 {
		return false
	}
	for _, effect := range effects {
		if _, ok := v.Effects[effect]; !ok {
			return false
		}
	}
	return true
}
