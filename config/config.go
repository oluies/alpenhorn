// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"

	"github.com/oluies/neverlur/errors"
	"github.com/oluies/neverlur/mixnet"
	"github.com/oluies/neverlur/pkg"
	"github.com/oluies/neverlur/pqsig"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson .

// SignedConfigVersion is the on-wire schema version produced by this
// codebase. v2 carries hybrid (Ed25519 || ML-DSA-65) signatures and
// hybrid identities. v1 records (classical-only) are no longer
// produced; the unmarshaler explicitly rejects them per Constitution
// Principle V "no silent downgrade".
const SignedConfigVersion = 2

// SignedConfig is an entry in a hash chain of configs.
type SignedConfig struct {
	Version int

	// Service is the name of the service this config corresponds to
	// (e.g., "AddFriend", "Dialing", or "Convo").
	Service string

	Created        time.Time
	Expires        time.Time
	PrevConfigHash string

	// Inner is the configuration specific to a service. The type of
	// the inner config should correspond to the the service name in
	// the signed config.
	Inner InnerConfig

	// Guardians is the set of keys that must sign the next config
	// to replace this config. Each Guardian carries both Ed25519 and
	// ML-DSA-65 public keys (R4-bound at generation).
	Guardians []Guardian

	// Signatures is a map from base32-encoded Ed25519 public key to
	// a hybrid signature. The value is HybridSignatureSize bytes:
	// 64 bytes of Ed25519 signature followed by 3309 bytes of
	// ML-DSA-65 signature, in fixed-width concatenation. Verify
	// rejects any value of wrong length.
	//
	// The map key is the classical (Ed25519) half of the guardian's
	// identity because that half is the stable, human-distributable
	// identifier; the ML-DSA-65 half is R4-derived from the same
	// underlying seed and bound to it.
	Signatures map[string][]byte

	// MinClientVersion is the minimum SignedConfigVersion that a
	// consumer must understand to safely parse this record. v2
	// records set this to 2 so that v1-only consumers reject the
	// record outright rather than silently fall through.
	MinClientVersion int
}

type InnerConfig interface {
	Validate() error

	UseLatestVersion()

	// The InnerConfig must be marshalable as JSON.
}

//easyjson:readable
type Guardian struct {
	Username string
	Key      ed25519.PublicKey

	// PQKey is the packed ML-DSA-65 public key (pqsig.PublicKeySize
	// bytes = 1952). R4-bound to Key via
	// pqsig.DeriveFromEd25519Seed(seed_of_Key); verifiers cannot
	// independently confirm the binding without the seed but it is
	// enforced operator-side at guardian-key-generation time.
	//
	// Required in v2 records; Validate rejects a guardian whose
	// PQKey is empty or wrong-sized.
	PQKey []byte
}

func (c *SignedConfig) SigningMessage() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("SignedConfig")

	clone := *c
	clone.Signatures = nil

	err := json.NewEncoder(buf).Encode(clone)
	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func VerifyConfigChain(configs ...*SignedConfig) error {
	if len(configs) < 2 {
		panic("short config chain")
	}

	for i, curr := range configs {
		if i == len(configs)-1 {
			break
		}
		prev := configs[i+1]

		if curr.PrevConfigHash != prev.Hash() {
			return errors.New("config %d: bad PrevConfigHash", i)
		}

		msg := curr.SigningMessage()
		verified := make(map[string]bool)
		for _, guardian := range prev.Guardians {
			keystr := base32.EncodeToString(guardian.Key)
			if err := verifyHybridGuardianSig(curr, &guardian, msg, keystr); err != nil {
				return errors.New("config %d: %s", i, err.Error())
			}
			verified[keystr] = true
		}
		for _, guardian := range curr.Guardians {
			keystr := base32.EncodeToString(guardian.Key)
			if verified[keystr] {
				continue
			}
			if err := verifyHybridGuardianSig(curr, &guardian, msg, keystr); err != nil {
				return errors.New("config %d: %s", i, err.Error())
			}
		}
	}

	return nil
}

func (c *SignedConfig) Verify() error {
	msg := c.SigningMessage()
	for _, guardian := range c.Guardians {
		keystr := base32.EncodeToString(guardian.Key)
		if err := verifyHybridGuardianSig(c, &guardian, msg, keystr); err != nil {
			return err
		}
	}
	return nil
}

// verifyHybridGuardianSig is the single per-guardian signature-check
// path used by Verify and VerifyConfigChain. It enforces the
// constitutional Principle V "no silent downgrade" property: both
// signature halves MUST verify; absence or invalidity of either is
// rejection.
func verifyHybridGuardianSig(c *SignedConfig, guardian *Guardian, msg []byte, keystr string) error {
	sig, ok := c.Signatures[keystr]
	if !ok {
		return errors.New("missing signature for key %s: %s", guardian.Username, keystr)
	}
	if len(sig) != HybridSignatureSize {
		return errors.New("wrong signature length for key %s: %s (got %d, want %d)", guardian.Username, keystr, len(sig), HybridSignatureSize)
	}
	var hs HybridSignature
	if err := hs.UnmarshalBytes(sig); err != nil {
		return errors.New("decode signature for key %s: %s: %s", guardian.Username, keystr, err.Error())
	}
	if !ed25519.Verify(guardian.Key, msg, hs.Ed[:]) {
		return errors.New("classical (ed25519) signature did not verify for key %s: %s", guardian.Username, keystr)
	}
	pqPub, err := pqsig.UnpackPublicKey(guardian.PQKey)
	if err != nil {
		return errors.New("bad guardian PQ key for %s: %s: %s", guardian.Username, keystr, err.Error())
	}
	if !pqsig.Verify(pqPub, msg, hs.PQ[:]) {
		return errors.New("post-quantum (ml-dsa-65) signature did not verify for key %s: %s", guardian.Username, keystr)
	}
	return nil
}

func (c *SignedConfig) Validate() error {
	if c.Version <= 0 {
		return errors.New("invalid version number: %d", c.Version)
	}
	if c.Version != SignedConfigVersion {
		return errors.New("unsupported SignedConfig version %d (this codebase produces and accepts v%d)", c.Version, SignedConfigVersion)
	}
	if c.MinClientVersion > SignedConfigVersion {
		return errors.New("MinClientVersion %d exceeds this codebase's SignedConfigVersion %d", c.MinClientVersion, SignedConfigVersion)
	}
	for i, guardian := range c.Guardians {
		if len(guardian.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for guardian %d: %v", i, guardian.Key)
		}
		if len(guardian.PQKey) != pqsig.PublicKeySize {
			return errors.New("invalid PQ key length for guardian %d: got %d, want %d", i, len(guardian.PQKey), pqsig.PublicKeySize)
		}
		if guardian.Username == "" {
			return errors.New("invalid username for guardian %d: %q", i, guardian.Username)
		}
	}

	if c.Service == "" {
		return errors.New("empty service name")
	}
	if c.Inner == nil {
		return errors.New("no inner config")
	}
	return c.Inner.Validate()
}

func (c *SignedConfig) Hash() string {
	msg := c.SigningMessage()
	h := sha512.Sum512_256(msg)
	return base32.EncodeToString(h[:])
}

//easyjson:readable
type signedConfigV1 struct {
	Version int

	Created        time.Time
	Expires        time.Time
	PrevConfigHash string

	Service string
	Inner   json.RawMessage

	Guardians []Guardian

	Signatures map[string][]byte
}

// signedConfigV2 is the JSON-friendly v2 form. Carried alongside (not
// in place of) signedConfigV1 so the old type definition stays parseable
// for any v1 record lying around in tests or backups. The runtime
// SignedConfig.UnmarshalJSON dispatches on the JSON-embedded Version
// field and refuses v1 records (per docs/wire-signed-config-v2.md).
type signedConfigV2 struct {
	Version int

	Created        time.Time
	Expires        time.Time
	PrevConfigHash string

	Service string
	Inner   json.RawMessage

	Guardians []Guardian

	Signatures map[string][]byte // each value is HybridSignatureSize bytes

	MinClientVersion int
}

func (c *SignedConfig) MarshalJSON() ([]byte, error) {
	switch c.Version {
	case 2:
		innerJSON, err := json.Marshal(c.Inner)
		if err != nil {
			return nil, err
		}
		c2 := &signedConfigV2{
			Version: 2,

			Created:        c.Created,
			Expires:        c.Expires,
			PrevConfigHash: c.PrevConfigHash,

			Service: c.Service,
			Inner:   innerJSON,

			Guardians:        c.Guardians,
			Signatures:       c.Signatures,
			MinClientVersion: c.MinClientVersion,
		}
		return json.Marshal(c2)
	case 1:
		return nil, errors.New("SignedConfig v1 is no longer emitted by this codebase; bump Version to %d (see docs/wire-signed-config-v2.md)", SignedConfigVersion)
	default:
		return nil, errors.New("unknown SignedConfig version: %d", c.Version)
	}
}

func (c *SignedConfig) UnmarshalJSON(data []byte) error {
	version, err := getVersionFromJSON(data)
	if err != nil {
		return err
	}

	switch version {
	case 2:
		c2 := new(signedConfigV2)
		err := json.Unmarshal(data, c2)
		if err != nil {
			return err
		}
		inner, err := decodeInner(c2.Service, c2.Inner)
		if err != nil {
			return err
		}
		c.Version = 2
		c.Created = c2.Created
		c.Expires = c2.Expires
		c.PrevConfigHash = c2.PrevConfigHash
		c.Service = c2.Service
		c.Inner = inner
		c.Guardians = c2.Guardians
		c.Signatures = c2.Signatures
		c.MinClientVersion = c2.MinClientVersion
	case 1:
		return errors.New("SignedConfig v1 records are not accepted by this codebase (no silent downgrade per constitution Principle V); see docs/wire-signed-config-v2.md")
	default:
		return errors.New("unknown SignedConfig version: %d", version)
	}

	return nil
}

func decodeInner(service string, rawJSON json.RawMessage) (InnerConfig, error) {
	registerMu.Lock()
	innerType, ok := registeredServices[service]
	registerMu.Unlock()
	if !ok {
		return nil, errors.New("unregistered service unmarshaling config: %q", service)
	}

	rawInner := reflect.New(innerType).Interface()
	err := json.Unmarshal(rawJSON, rawInner)
	if err != nil {
		return nil, err
	}
	inner := rawInner.(InnerConfig)
	return inner, nil
}

var (
	registerMu sync.Mutex
	// registeredServices is a map from service name (e.g., "AddFriend")
	// to its corresponding inner config type.
	registeredServices = make(map[string]reflect.Type)
)

func RegisterService(service string, innerConfigType InnerConfig) {
	registerMu.Lock()
	registeredServices[service] = reflect.TypeOf(innerConfigType).Elem()
	registerMu.Unlock()
}

func init() {
	RegisterService("AddFriend", &AddFriendConfig{})
	RegisterService("Dialing", &DialingConfig{})
}

const AddFriendConfigVersion = 2

type AddFriendConfig struct {
	Version     int
	Coordinator CoordinatorConfig
	PKGServers  []pkg.PublicServerConfig
	MixServers  []mixnet.PublicServerConfig
	CDNServer   CDNServerConfig
	Registrar   RegistrarConfig
}

func (c *AddFriendConfig) UseLatestVersion() {
	c.Version = AddFriendConfigVersion
}

//easyjson:readable
type RegistrarConfig struct {
	Key     ed25519.PublicKey
	Address string
}

//easyjson:readable
type CoordinatorConfig struct {
	Key     ed25519.PublicKey
	Address string
}

//easyjson:readable
type CDNServerConfig struct {
	Key     ed25519.PublicKey
	Address string
}

//easyjson:readable
type addFriendV1 struct {
	Version       int
	Coordinator   keyAddr
	PKGServers    []keyAddr
	MixServers    []keyAddr
	CDNServer     keyAddr
	RegistrarHost string
}

//easyjson:readable
type addFriendV2 struct {
	Version     int
	Coordinator keyAddr
	PKGServers  []keyAddr
	MixServers  []keyAddr
	CDNServer   keyAddr
	Registrar   keyAddr
}

//easyjson:readable
type keyAddr struct {
	Key     ed25519.PublicKey
	Address string
}

func (c *AddFriendConfig) v1() (*addFriendV1, error) {
	c1 := &addFriendV1{
		Version:       1,
		Coordinator:   keyAddr{c.Coordinator.Key, c.Coordinator.Address},
		PKGServers:    make([]keyAddr, len(c.PKGServers)),
		MixServers:    make([]keyAddr, len(c.MixServers)),
		CDNServer:     keyAddr{c.CDNServer.Key, c.CDNServer.Address},
		RegistrarHost: c.Registrar.Address,
	}
	for i, srv := range c.PKGServers {
		c1.PKGServers[i] = keyAddr{srv.Key, srv.Address}
	}
	for i, srv := range c.MixServers {
		c1.MixServers[i] = keyAddr{srv.Key, srv.Address}
	}
	return c1, nil
}

func (c *AddFriendConfig) v2() (*addFriendV2, error) {
	c2 := &addFriendV2{
		Version:     2,
		Coordinator: keyAddr{c.Coordinator.Key, c.Coordinator.Address},
		PKGServers:  make([]keyAddr, len(c.PKGServers)),
		MixServers:  make([]keyAddr, len(c.MixServers)),
		CDNServer:   keyAddr{c.CDNServer.Key, c.CDNServer.Address},
		Registrar:   keyAddr{c.Registrar.Key, c.Registrar.Address},
	}
	for i, srv := range c.PKGServers {
		c2.PKGServers[i] = keyAddr{srv.Key, srv.Address}
	}
	for i, srv := range c.MixServers {
		c2.MixServers[i] = keyAddr{srv.Key, srv.Address}
	}
	return c2, nil
}

func (c *AddFriendConfig) fromV1(c1 *addFriendV1) error {
	c.Version = 1
	c.Coordinator = CoordinatorConfig{c1.Coordinator.Key, c1.Coordinator.Address}
	c.PKGServers = make([]pkg.PublicServerConfig, len(c1.PKGServers))
	c.MixServers = make([]mixnet.PublicServerConfig, len(c1.MixServers))
	c.CDNServer = CDNServerConfig{c1.CDNServer.Key, c1.CDNServer.Address}
	for i, srv := range c1.PKGServers {
		c.PKGServers[i] = pkg.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	for i, srv := range c1.MixServers {
		c.MixServers[i] = mixnet.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	c.Registrar.Address = c1.RegistrarHost
	return nil
}

func (c *AddFriendConfig) fromV2(c2 *addFriendV2) error {
	c.Version = 2
	c.Coordinator = CoordinatorConfig{c2.Coordinator.Key, c2.Coordinator.Address}
	c.PKGServers = make([]pkg.PublicServerConfig, len(c2.PKGServers))
	c.MixServers = make([]mixnet.PublicServerConfig, len(c2.MixServers))
	c.CDNServer = CDNServerConfig{c2.CDNServer.Key, c2.CDNServer.Address}
	for i, srv := range c2.PKGServers {
		c.PKGServers[i] = pkg.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	for i, srv := range c2.MixServers {
		c.MixServers[i] = mixnet.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	c.Registrar = RegistrarConfig{c2.Registrar.Key, c2.Registrar.Address}
	return nil
}

func (c *AddFriendConfig) Validate() error {
	if c.Version <= 0 {
		return errors.New("invalid version number: %d", c.Version)
	}
	if c.Coordinator.Address == "" {
		return errors.New("empty address for coordinator")
	}
	if len(c.Coordinator.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for coordinator: %#v", c.Coordinator.Key)
	}

	for i, mix := range c.MixServers {
		if len(mix.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for mixer %d: %v", i, mix.Key)
		}
		if mix.Address == "" {
			return errors.New("empty address for mix server %d", i)
		}
	}

	if c.CDNServer.Address == "" {
		return errors.New("empty address for cdn server")
	}
	if len(c.CDNServer.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for cdn: %v", c.CDNServer.Key)
	}

	for i, pkg := range c.PKGServers {
		if len(pkg.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for pkg %d: %v", i, pkg.Key)
		}
		if pkg.Address == "" {
			return errors.New("empty address for pkg %d", i)
		}
	}

	return nil
}

func (c *AddFriendConfig) MarshalJSON() ([]byte, error) {
	switch c.Version {
	case 1:
		c1, err := c.v1()
		if err != nil {
			return nil, err
		}
		return json.Marshal(c1)
	case 2:
		c2, err := c.v2()
		if err != nil {
			return nil, err
		}
		return json.Marshal(c2)
	default:
		return nil, errors.New("unknown AddFriendConfig version: %d", c.Version)
	}
}

func (c *AddFriendConfig) UnmarshalJSON(data []byte) error {
	version, err := getVersionFromJSON(data)
	if err != nil {
		return err
	}
	switch version {
	case 1:
		c1 := new(addFriendV1)
		err := json.Unmarshal(data, c1)
		if err != nil {
			return err
		}
		return c.fromV1(c1)
	case 2:
		c2 := new(addFriendV2)
		err := json.Unmarshal(data, c2)
		if err != nil {
			return err
		}
		return c.fromV2(c2)
	default:
		return errors.New("unknown AddFriendConfig version: %d", version)
	}
}

const DialingConfigVersion = 1

type DialingConfig struct {
	Version     int
	Coordinator CoordinatorConfig
	MixServers  []mixnet.PublicServerConfig
	CDNServer   CDNServerConfig
}

func (c *DialingConfig) UseLatestVersion() {
	c.Version = DialingConfigVersion
}

//easyjson:readable
type dialingV1 struct {
	Version     int
	Coordinator keyAddr
	MixServers  []keyAddr
	CDNServer   keyAddr
}

func (c *DialingConfig) v1() (*dialingV1, error) {
	c1 := &dialingV1{
		Version:     1,
		Coordinator: keyAddr{c.Coordinator.Key, c.Coordinator.Address},
		MixServers:  make([]keyAddr, len(c.MixServers)),
		CDNServer:   keyAddr{c.CDNServer.Key, c.CDNServer.Address},
	}
	for i, srv := range c.MixServers {
		c1.MixServers[i] = keyAddr{srv.Key, srv.Address}
	}
	return c1, nil
}

func (c *DialingConfig) fromV1(c1 *dialingV1) error {
	c.Version = 1
	c.Coordinator = CoordinatorConfig{c1.Coordinator.Key, c1.Coordinator.Address}
	c.MixServers = make([]mixnet.PublicServerConfig, len(c1.MixServers))
	c.CDNServer = CDNServerConfig{c1.CDNServer.Key, c1.CDNServer.Address}
	for i, srv := range c1.MixServers {
		c.MixServers[i] = mixnet.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	return nil
}

func (c *DialingConfig) MarshalJSON() ([]byte, error) {
	switch c.Version {
	case 1:
		c1, err := c.v1()
		if err != nil {
			return nil, err
		}
		return json.Marshal(c1)
	default:
		return nil, errors.New("unknown DialingConfig version: %d", c.Version)
	}
}

func (c *DialingConfig) UnmarshalJSON(data []byte) error {
	version, err := getVersionFromJSON(data)
	if err != nil {
		return err
	}
	switch version {
	case 1:
		c1 := new(dialingV1)
		err := json.Unmarshal(data, c1)
		if err != nil {
			return err
		}
		return c.fromV1(c1)
	default:
		return errors.New("unknown DialingConfig version: %d", version)
	}
}

func (c *DialingConfig) Validate() error {
	if c.Version <= 0 {
		return errors.New("invalid version number: %d", c.Version)
	}
	if c.Coordinator.Address == "" {
		return errors.New("empty address for coordinator")
	}
	if len(c.Coordinator.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for coordinator: %#v", c.Coordinator.Key)
	}

	for i, mix := range c.MixServers {
		if len(mix.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for mixer %d: %v", i, mix.Key)
		}
		if mix.Address == "" {
			return errors.New("empty address for mix server %d", i)
		}
	}

	if c.CDNServer.Address != "" && len(c.CDNServer.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for cdn: %v", c.CDNServer.Key)
	}

	return nil
}

func getVersionFromJSON(data []byte) (int, error) {
	type ver struct {
		Version int
	}
	v := new(ver)
	err := json.Unmarshal(data, v)
	if err != nil {
		return -1, err
	}
	return v.Version, nil
}
