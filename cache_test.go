// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v2/acme"
	"go.uber.org/zap"
)

func TestNewCache(t *testing.T) {
	noop := func(Certificate) (*Config, error) { return new(Config), nil }
	c := NewCache(CacheOptions{GetConfigForCert: noop})
	defer c.Stop()

	c.optionsMu.RLock()
	defer c.optionsMu.RUnlock()

	if c.options.RenewCheckInterval != DefaultRenewCheckInterval {
		t.Errorf("Expected RenewCheckInterval to be set to default value, but it wasn't: %s", c.options.RenewCheckInterval)
	}
	if c.options.OCSPCheckInterval != DefaultOCSPCheckInterval {
		t.Errorf("Expected OCSPCheckInterval to be set to default value, but it wasn't: %s", c.options.OCSPCheckInterval)
	}
	if c.options.GetConfigForCert == nil {
		t.Error("Expected GetConfigForCert to be set, but it was nil")
	}
	if c.cache == nil {
		t.Error("Expected cache to be set, but it was nil")
	}
	if c.stopChan == nil {
		t.Error("Expected stopChan to be set, but it was nil")
	}
}

func TestCacheStopCancelsARIRefresh(t *testing.T) {
	requested := make(chan struct{}, 1)
	requestCanceled := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requested <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
			select {
			case requestCanceled <- struct{}{}:
			default:
			}
		case <-release:
			http.Error(w, "released for test cleanup", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	storage := &FileStorage{Path: t.TempDir()}
	var cfg *Config
	cache := NewCache(CacheOptions{
		GetConfigForCert:   func(Certificate) (*Config, error) { return cfg, nil },
		RenewCheckInterval: 10 * time.Millisecond,
		OCSPCheckInterval:  time.Hour,
		Logger:             zap.NewNop(),
	})
	var stopOnce sync.Once
	stopped := make(chan struct{})
	stopCache := func() {
		stopOnce.Do(func() {
			go func() {
				cache.Stop()
				close(stopped)
			}()
		})
	}
	t.Cleanup(func() {
		stopCache()
		// Release the HTTP request even on pre-fix code, where Stop cannot cancel it.
		close(release)
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("cache did not stop after releasing the HTTP request")
		}
	})
	cfg = New(cache, Config{
		Storage: storage,
		Logger:  zap.NewNop(),
	})
	issuer := NewACMEIssuer(cfg, ACMEIssuer{
		CA:     server.URL + "/directory",
		Logger: zap.NewNop(),
	})
	cfg.Issuers = []Issuer{issuer}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"maintenance.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := PEMEncodePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	retryAfter := now.Add(-time.Minute)
	// Keep issuance scheduled in the future to isolate synchronous ARI refresh
	// from asynchronous renewal jobs, which Stop does not wait for.
	ari := &acme.RenewalInfo{
		RetryAfter:   &retryAfter,
		SelectedTime: now.Add(30 * time.Minute),
	}
	ari.SuggestedWindow.Start = now.Add(20 * time.Minute)
	ari.SuggestedWindow.End = now.Add(40 * time.Minute)
	ctx := context.Background()
	err = cfg.saveCertResource(ctx, issuer, CertificateResource{
		SANs:           leaf.DNSNames,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  keyPEM,
		IssuerData:     mustJSON(acme.Certificate{RenewalInfo: ari}),
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := cfg.CacheManagedCertificate(ctx, leaf.DNSNames[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.NeedsRenewal(cfg) {
		t.Fatal("test certificate is already due for issuance; expected only ARI refresh")
	}

	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance did not request the ACME directory for ARI refresh")
	}
	started := time.Now()
	stopCache()
	select {
	case <-stopped:
		t.Logf("Stop returned after %s while ARI directory retrieval was stalled", time.Since(started))
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop blocked on stalled maintenance ARI refresh")
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Error("Stop did not cancel the maintenance HTTP request")
	}
}
