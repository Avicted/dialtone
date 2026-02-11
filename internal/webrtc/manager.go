package webrtc

import (
	"fmt"
	"sync"
	"time"

	pionwebrtc "github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

type Manager struct {
	mu      sync.Mutex
	api     *pionwebrtc.API
	config  pionwebrtc.Configuration
	peers   map[string]*peer
	onICE   func(peerID, candidate string)
	onState func(peerID string, state pionwebrtc.PeerConnectionState)
	onTrack func(peerID string, track *pionwebrtc.TrackRemote)
}

type peer struct {
	id    string
	pc    *pionwebrtc.PeerConnection
	track *pionwebrtc.TrackLocalStaticSample
}

func NewManager(config pionwebrtc.Configuration, onICE func(peerID, candidate string), onState func(peerID string, state pionwebrtc.PeerConnectionState), onTrack func(peerID string, track *pionwebrtc.TrackRemote)) (*Manager, error) {
	m := &pionwebrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return nil, fmt.Errorf("register codecs: %w", err)
	}
	api := pionwebrtc.NewAPI(pionwebrtc.WithMediaEngine(m))
	return &Manager{
		api:     api,
		config:  config,
		peers:   make(map[string]*peer),
		onICE:   onICE,
		onState: onState,
		onTrack: onTrack,
	}, nil
}

func (m *Manager) CreateOffer(peerID string) (string, error) {
	p, err := m.ensurePeer(peerID)
	if err != nil {
		return "", err
	}
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		return "", fmt.Errorf("create offer: %w", err)
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		return "", fmt.Errorf("set local offer: %w", err)
	}
	return offer.SDP, nil
}

func (m *Manager) HandleOffer(peerID, sdp string) (string, error) {
	p, err := m.ensurePeer(peerID)
	if err != nil {
		return "", err
	}
	offer := pionwebrtc.SessionDescription{Type: pionwebrtc.SDPTypeOffer, SDP: sdp}
	if err := p.pc.SetRemoteDescription(offer); err != nil {
		return "", fmt.Errorf("set remote offer: %w", err)
	}
	answer, err := p.pc.CreateAnswer(nil)
	if err != nil {
		return "", fmt.Errorf("create answer: %w", err)
	}
	if err := p.pc.SetLocalDescription(answer); err != nil {
		return "", fmt.Errorf("set local answer: %w", err)
	}
	return answer.SDP, nil
}

func (m *Manager) HandleAnswer(peerID, sdp string) error {
	p, err := m.ensurePeer(peerID)
	if err != nil {
		return err
	}
	answer := pionwebrtc.SessionDescription{Type: pionwebrtc.SDPTypeAnswer, SDP: sdp}
	if err := p.pc.SetRemoteDescription(answer); err != nil {
		return fmt.Errorf("set remote answer: %w", err)
	}
	return nil
}

func (m *Manager) AddICECandidate(peerID, candidate string) error {
	p, err := m.ensurePeer(peerID)
	if err != nil {
		return err
	}
	return p.pc.AddICECandidate(pionwebrtc.ICECandidateInit{Candidate: candidate})
}

func (m *Manager) ClosePeer(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[peerID]
	if !ok {
		return
	}
	delete(m.peers, peerID)
	_ = p.pc.Close()
}

func (m *Manager) CloseAll() {
	m.mu.Lock()
	peers := m.peers
	m.peers = make(map[string]*peer)
	m.mu.Unlock()
	for _, p := range peers {
		_ = p.pc.Close()
	}
}

func (m *Manager) WriteSample(data []byte, duration time.Duration) error {
	m.mu.Lock()
	peers := make([]*peer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.Unlock()
	if len(peers) == 0 {
		return nil
	}
	var lastErr error
	for _, p := range peers {
		if err := p.track.WriteSample(media.Sample{Data: data, Duration: duration}); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (m *Manager) ensurePeer(peerID string) (*peer, error) {
	if peerID == "" {
		return nil, fmt.Errorf("peer id is required")
	}
	m.mu.Lock()
	if p, ok := m.peers[peerID]; ok {
		m.mu.Unlock()
		return p, nil
	}
	m.mu.Unlock()

	pc, err := m.api.NewPeerConnection(m.config)
	if err != nil {
		return nil, fmt.Errorf("new peer connection: %w", err)
	}
	track, err := pionwebrtc.NewTrackLocalStaticSample(pionwebrtc.RTPCodecCapability{MimeType: pionwebrtc.MimeTypeOpus}, "audio", "dialtone")
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("new audio track: %w", err)
	}
	if _, err := pc.AddTrack(track); err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("add audio track: %w", err)
	}

	pc.OnICECandidate(func(c *pionwebrtc.ICECandidate) {
		if c == nil || m.onICE == nil {
			return
		}
		m.onICE(peerID, c.ToJSON().Candidate)
	})
	pc.OnConnectionStateChange(func(state pionwebrtc.PeerConnectionState) {
		if m.onState != nil {
			m.onState(peerID, state)
		}
	})
	pc.OnTrack(func(track *pionwebrtc.TrackRemote, _ *pionwebrtc.RTPReceiver) {
		if m.onTrack != nil {
			m.onTrack(peerID, track)
		}
	})

	p := &peer{id: peerID, pc: pc, track: track}
	m.mu.Lock()
	m.peers[peerID] = p
	m.mu.Unlock()
	return p, nil
}
