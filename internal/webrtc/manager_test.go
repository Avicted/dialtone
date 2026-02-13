package webrtc

import (
	"strings"
	"testing"
	"time"

	pionwebrtc "github.com/pion/webrtc/v4"
)

func TestManagerEnsurePeerValidationAndReuse(t *testing.T) {
	m, err := NewManager(pionwebrtc.Configuration{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() {
		m.CloseAll()
	})

	if _, err := m.ensurePeer(""); err == nil || !strings.Contains(err.Error(), "peer id is required") {
		t.Fatalf("expected peer id validation error, got %v", err)
	}

	p1, err := m.ensurePeer("peer-1")
	if err != nil {
		t.Fatalf("ensurePeer create: %v", err)
	}
	p2, err := m.ensurePeer("peer-1")
	if err != nil {
		t.Fatalf("ensurePeer reuse: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("expected ensurePeer to reuse existing peer instance")
	}
}

func TestManagerOfferAnswerFlow(t *testing.T) {
	offerer, err := NewManager(pionwebrtc.Configuration{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewManager offerer: %v", err)
	}
	t.Cleanup(func() { offerer.CloseAll() })

	answerer, err := NewManager(pionwebrtc.Configuration{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewManager answerer: %v", err)
	}
	t.Cleanup(func() { answerer.CloseAll() })

	offer, err := offerer.CreateOffer("peer-a")
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if strings.TrimSpace(offer) == "" {
		t.Fatalf("expected non-empty SDP offer")
	}

	answer, err := answerer.HandleOffer("peer-a", offer)
	if err != nil {
		t.Fatalf("HandleOffer: %v", err)
	}
	if strings.TrimSpace(answer) == "" {
		t.Fatalf("expected non-empty SDP answer")
	}

	if err := offerer.HandleAnswer("peer-a", answer); err != nil {
		t.Fatalf("HandleAnswer: %v", err)
	}

	if err := offerer.HandleAnswer("peer-a", "invalid-sdp"); err == nil {
		t.Fatalf("expected invalid answer SDP to fail")
	}
}

func TestManagerAddICECandidateWriteAndClose(t *testing.T) {
	m, err := NewManager(pionwebrtc.Configuration{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() {
		m.CloseAll()
	})

	if err := m.WriteSample([]byte{1, 2, 3}, 20*time.Millisecond); err != nil {
		t.Fatalf("WriteSample with no peers should be nil, got %v", err)
	}

	if _, err := m.CreateOffer("peer-ws"); err != nil {
		t.Fatalf("CreateOffer peer-ws: %v", err)
	}

	if err := m.WriteSample([]byte{1, 2, 3}, 20*time.Millisecond); err != nil {
		t.Fatalf("WriteSample with peer: %v", err)
	}

	if err := m.AddICECandidate("peer-ws", "not-a-valid-candidate"); err == nil {
		t.Fatalf("expected invalid ICE candidate to fail")
	}

	m.ClosePeer("peer-ws")
	m.ClosePeer("peer-ws")
	m.CloseAll()
}
