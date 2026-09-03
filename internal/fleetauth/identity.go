package fleetauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const identitySchema = 1

type Identity struct {
	nodeID     uuid.UUID
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

type identityFile struct {
	Schema     int    `json:"schema"`
	NodeID     string `json:"node_id"`
	PrivateKey string `json:"private_key"`
}

func LoadOrCreateIdentity(stateDir string, nodeID uuid.UUID) (*Identity, error) {
	if nodeID == uuid.Nil {
		return nil, errors.New("non-zero core node ID is required")
	}
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("core node state directory must be absolute")
	}
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(stateDir, ".identity.lock")
	lockFD, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open node identity lock: %w", err)
	}
	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFD, &lockStat); err != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Nlink != 1 {
		_ = unix.Close(lockFD)
		return nil, errors.New("node identity lock must be a single-link regular file")
	}
	lock := os.NewFile(uintptr(lockFD), lockPath)
	if lock == nil {
		_ = unix.Close(lockFD)
		return nil, errors.New("open node identity lock")
	}
	defer lock.Close()
	if err := lock.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("protect node identity lock: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock node identity: %w", err)
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()

	path := filepath.Join(stateDir, "identity.json")
	identity, err := loadIdentity(path, nodeID)
	if err == nil {
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate core node identity: %w", err)
	}
	record := identityFile{
		Schema:     identitySchema,
		NodeID:     nodeID.String(),
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode core node identity: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeAtomic(path, encoded); err != nil {
		return nil, err
	}
	return &Identity{nodeID: nodeID, privateKey: privateKey, now: time.Now}, nil
}

func (i *Identity) NodeID() uuid.UUID {
	return i.nodeID
}

func (i *Identity) PublicKey() ed25519.PublicKey {
	publicKey := i.privateKey.Public().(ed25519.PublicKey)
	return ed25519.PublicKey(append([]byte(nil), publicKey...))
}

func (i *Identity) EncodedPublicKey() string {
	return base64.RawURLEncoding.EncodeToString(i.PublicKey())
}

func (i *Identity) Sign(req *http.Request, body []byte) error {
	if i == nil || i.nodeID == uuid.Nil || len(i.privateKey) != ed25519.PrivateKeySize {
		return errors.New("core node identity is unavailable")
	}
	return signRequest(req, body, i.nodeID, i.privateKey, i.now())
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create core node state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect core node state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("core node state path must be a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect core node state directory: %w", err)
	}
	return nil
}

func loadIdentity(path string, expectedNodeID uuid.UUID) (*Identity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("core node identity must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, errors.New("core node identity permissions must be 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open core node identity: %w", err)
	}
	defer file.Close()
	limited := io.LimitReader(file, 4097)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var record identityFile
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode core node identity: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if record.Schema != identitySchema || record.NodeID != expectedNodeID.String() {
		return nil, errors.New("core node identity does not match configured node")
	}
	privateKey, err := decodeCanonicalRawURL(record.PrivateKey, ed25519.PrivateKeySize)
	if err != nil {
		return nil, errors.New("core node identity contains an invalid private key")
	}
	return &Identity{nodeID: expectedNodeID, privateKey: ed25519.PrivateKey(privateKey), now: time.Now}, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("core node identity contains trailing data")
	}
	return nil
}

func writeAtomic(path string, contents []byte) (returnErr error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return fmt.Errorf("create temporary core node identity: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary core node identity: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write temporary core node identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary core node identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary core node identity: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate core node identity: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open core node state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync core node state directory: %w", err)
	}
	return nil
}

func ReadEnrollmentToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", errors.New("enrollment token must be a regular 0600 file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read enrollment token: %w", err)
	}
	token := string(bytes.TrimSpace(contents))
	if _, err := decodeCanonicalRawURL(token, 32); err != nil {
		return "", errors.New("enrollment token file is invalid")
	}
	return token, nil
}

// DestroyEnrollmentToken overwrites and truncates the local plaintext before
// unlinking it. Failure to unlink is still returned even though the contents
// have already been cleared.
func DestroyEnrollmentToken(path, expectedToken string) error {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open enrollment token for destruction: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("inspect enrollment token for destruction: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		_ = unix.Close(fd)
		return errors.New("enrollment token must be a private, unlinked regular file")
	}
	if stat.Size < 1 || stat.Size > 256 {
		_ = unix.Close(fd)
		return errors.New("enrollment token file has an invalid size")
	}
	contents := make([]byte, stat.Size)
	n, readErr := unix.Read(fd, contents)
	if readErr != nil || n != len(contents) {
		_ = unix.Close(fd)
		return errors.New("read enrollment token before destruction")
	}
	currentToken := bytes.TrimSpace(contents)
	if subtle.ConstantTimeCompare(currentToken, []byte(expectedToken)) != 1 {
		_ = unix.Close(fd)
		return errors.New("enrollment token changed before destruction")
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("rewind enrollment token for destruction: %w", err)
	}
	zeroes := make([]byte, stat.Size)
	for len(zeroes) > 0 {
		written, err := unix.Write(fd, zeroes)
		if err != nil || written < 1 {
			_ = unix.Close(fd)
			return errors.New("overwrite enrollment token")
		}
		zeroes = zeroes[written:]
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("sync destroyed enrollment token: %w", err)
	}
	if err := unix.Ftruncate(fd, 0); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("truncate enrollment token: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close destroyed enrollment token: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove destroyed enrollment token: %w", err)
	}
	return nil
}
