package ippool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"sync"
)

var (
	ErrPoolExhausted = errors.New("IP pool exhausted")
	ErrIPAlreadyUsed = errors.New("IP already in use")
	ErrIPNotFound    = errors.New("IP not found in pool")
)

type Pool struct {
	mu      sync.Mutex
	network *net.IPNet
	baseIP  uint32
	maxHost uint32
	bitset  []uint64 // 1 bit per host offset; bit set = assigned
	count   uint32   // number of assigned IPs
	next    uint32   // next candidate host offset for fast scan
}

func New(cidr string) (*Pool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ones, b := network.Mask.Size()
	if b != 32 {
		return nil, fmt.Errorf("only IPv4 supported")
	}

	baseIP := binary.BigEndian.Uint32(network.IP.To4())
	maxHost := uint32(1<<(b-ones)) - 1 // broadcast = maxHost

	// Allocate bitset: one bit per possible host offset (0..maxHost)
	words := (maxHost + 64) / 64
	bs := make([]uint64, words)

	// Reserve .0 (network) and .1 (gateway)
	bs[0] |= 0b11 // offsets 0 and 1

	return &Pool{
		network: network,
		baseIP:  baseIP,
		maxHost: maxHost,
		bitset:  bs,
		count:   2, // network + gateway
		next:    2,
	}, nil
}

func (p *Pool) Allocate() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	usable := p.maxHost - 1 // exclude network (.0) and broadcast (.maxHost)
	if p.count > usable {
		return "", ErrPoolExhausted
	}

	// Start scanning from p.next, wrapping around once
	offset := p.next
	for {
		if offset >= p.maxHost {
			offset = 2
		}
		word := offset / 64
		bit := offset % 64
		if p.bitset[word]&(1<<bit) == 0 {
			p.bitset[word] |= 1 << bit
			p.count++
			p.next = offset + 1
			return p.offsetToIP(offset) + "/32", nil
		}
		offset++
		if offset == p.next {
			return "", ErrPoolExhausted
		}
	}
}

func (p *Pool) Release(ip string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	cleanIP := stripMask(ip)
	offset, ok := p.ipToOffset(cleanIP)
	if !ok {
		return ErrIPNotFound
	}

	word := offset / 64
	bit := offset % 64
	if p.bitset[word]&(1<<bit) == 0 {
		return ErrIPNotFound
	}
	p.bitset[word] &^= 1 << bit
	p.count--

	// Hint: next scan can start from this freed offset
	if offset < p.next {
		p.next = offset
	}
	return nil
}

func (p *Pool) Reserve(ip string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	cleanIP := stripMask(ip)
	offset, ok := p.ipToOffset(cleanIP)
	if !ok {
		return fmt.Errorf("IP %s not in pool network", cleanIP)
	}

	word := offset / 64
	bit := offset % 64
	if p.bitset[word]&(1<<bit) != 0 {
		return ErrIPAlreadyUsed
	}
	p.bitset[word] |= 1 << bit
	p.count++
	return nil
}

func (p *Pool) GatewayIP() string {
	return p.offsetToIP(1) + "/16"
}

// AssignedCount returns the number of assigned IPs (including network+gateway).
func (p *Pool) AssignedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return int(p.count)
}

// FreeCount returns the number of free usable IPs.
func (p *Pool) FreeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Total words popcount - gives exact assigned count
	var total int
	for _, w := range p.bitset {
		total += bits.OnesCount64(w)
	}
	usable := int(p.maxHost) - 1 // exclude .0 and broadcast
	return usable - total + 2    // +2 because network and gateway are in bitset but not usable
}

func (p *Pool) offsetToIP(offset uint32) string {
	ipInt := p.baseIP + offset
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip.String()
}

func (p *Pool) ipToOffset(ipStr string) (uint32, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	ipInt := binary.BigEndian.Uint32(ip4)
	if ipInt < p.baseIP || ipInt > p.baseIP+p.maxHost {
		return 0, false
	}
	return ipInt - p.baseIP, true
}

func stripMask(ip string) string {
	for i := 0; i < len(ip); i++ {
		if ip[i] == '/' {
			return ip[:i]
		}
	}
	return ip
}
