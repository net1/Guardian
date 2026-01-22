package main

// SignatureType identifies the source of a signature for threshold selection
type SignatureType int

const (
	SigNormalized  SignatureType = iota // Normalized body - highest confidence
	SigRaw                              // Raw body - medium confidence
	SigURL                              // URL-based - high confidence for phishing
	SigSubject                          // Subject-based - medium confidence
	SigAttachment                       // Attachment - lower confidence
)

func (s SignatureType) String() string {
	switch s {
	case SigNormalized:
		return "normalized"
	case SigRaw:
		return "raw"
	case SigURL:
		return "url"
	case SigSubject:
		return "subject"
	case SigAttachment:
		return "attachment"
	default:
		return "unknown"
	}
}

// TypedSignature holds a signature with its type for threshold selection
type TypedSignature struct {
	Hash string
	Type SignatureType
}

type AnalysisResult struct {
	Action         string  `json:"action"`
	Label          string  `json:"label,omitempty"`
	ProximityMatch bool    `json:"proximity_match"`
	Distance       int     `json:"distance,omitempty"`
	Confidence     float64 `json:"confidence,omitempty"`
	MatchType      string  `json:"match_type,omitempty"`
}

type SyncResponse struct {
	NewSeq int      `json:"new_seq"`
	Action string   `json:"action"`
	Ops    []SyncOp `json:"ops"`
}

type SyncOp struct {
	Action string   `json:"action"`
	Bands  []string `json:"bands"`
}

type ScanResult struct {
	Hashes    []string `json:"hashes"`
	Timestamp int64    `json:"timestamp"`
}
