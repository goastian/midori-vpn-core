package ippool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

var (
	ErrPoolExhausted = errors.New("IP pool exhausted")
	ErrIPAlreadyUsed = errors.New("IP already in use")
	ErrIPNotFound    = errors.New("IP not found in pool")
)

type Pool struct {
	mu       sync.Mutex
	network  *net.IPNet
	baseIP   uint32
	maxHost  uint32
	assigned map[string]bool // "10.8.0.2" -> true
	next     uint32          // next candidate host offset
}

func New(cidr string) (*Pool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 supported")
	}

	baseIP := binary.BigEndian.Uint32(network.IP.To4())
	maxHost := uint32(1<<(bits-ones)) - 1 // broadcast = maxHost

	return &Pool{
		network:  network,
		baseIP:   baseIP,
		maxHost:  maxHost,
		assigned: make(map[string]bool),
		next:     2, // .0 = network, .1 = gateway (server)
	}, nil
}

func (p *Pool) Allocate() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	startOffset := p.next
	for {
		if p.next >= p.maxHost {
			p.next = 2 // wrap around
		}
		ip := p.offsetToIP(p.next)
		if !p.assigned[ip] {
			p.assigned[ip] = true
			p.next++
			return ip + "/32", nil
		}
		p.next++
		if p.next == startOffset {
			return "", ErrPoolExhausted
		}
	}
}

func (p *Pool) Release(ip string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Strip /32 suffix if present
	cleanIP := stripMask(ip)

	if !p.assigned[cleanIP] {
		return ErrIPNotFound
	}
	delete(p.assigned, cleanIP)
	return nil
}

func (p *Pool) Reserve(ip string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	cleanIP := stripMask(ip)

	if p.assigned[cleanIP] {
		return ErrIPAlreadyUsed
	}
	p.assigned[cleanIP] = true
	return nil
}

func (p *Pool) GatewayIP() string {
	return p.offsetToIP(1) + "/16"
}

func (p *Pool) offsetToIP(offset uint32) string {
	ipInt := p.baseIP + offset
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip.String()
}

func stripMask(ip string) string {
	for i := 0; i < len(ip); i++ {
		if ip[i] == '/' {
			return ip[:i]
		}
	}
	return ip
}
