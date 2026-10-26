package certmagic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

const dummyCA = "https://example.com/acme/directory"

func TestACMEIssuerIssueContext(t *testing.T) {
	for _, tc := range []struct {
		name        string
		timeout     time.Duration
		cancelAfter time.Duration
		wantErr     error
	}{
		{"issue timeout", 100 * time.Millisecond, 0, context.DeadlineExceeded},
		{"parent cancellation", time.Hour, 25 * time.Millisecond, context.Canceled},
		{"zero timeout", 0, 250 * time.Millisecond, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requested := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				select {
				case requested <- struct{}{}:
				default:
				}
				<-r.Context().Done()
			}))
			t.Cleanup(server.Close)

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keyPEM, err := PEMEncodePrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			issuer := NewACMEIssuer(&Config{Storage: &FileStorage{Path: t.TempDir()}}, ACMEIssuer{
				CA:                server.URL + "/directory",
				Email:             "test@example.com",
				AccountKeyPEM:     string(keyPEM),
				IssueTimeout:      tc.timeout,
				CertObtainTimeout: 10 * time.Millisecond,
				Logger:            zap.NewNop(),
			})
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			result := make(chan error, 1)
			started := time.Now()
			go func() {
				_, err := issuer.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"example.com"}})
				result <- err
			}()

			select {
			case <-requested:
			case err := <-result:
				t.Fatalf("Issue returned before requesting the directory: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Issue did not request the directory")
			}
			if tc.cancelAfter > 0 {
				select {
				case err := <-result:
					t.Fatalf("Issue returned before parent cancellation: %v", err)
				case <-time.After(tc.cancelAfter):
				}
				cancel()
			}
			select {
			case err := <-result:
				// Account lookup currently formats errors with %v, losing their identity.
				if err == nil || !strings.Contains(err.Error(), tc.wantErr.Error()) {
					t.Errorf("Issue error = %v, want %v", err, tc.wantErr)
				}
				t.Logf("Issue returned after %s: %v", time.Since(started), err)
			case <-time.After(2 * time.Second):
				t.Fatal("Issue did not return within the operation's time bound")
			}
			if tc.cancelAfter == 0 {
				if err := ctx.Err(); err != nil {
					t.Fatalf("Issue canceled parent context: %v", err)
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/health", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := server.Client().Do(req)
				if err != nil {
					t.Fatalf("parent context cannot make another request: %v", err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					t.Errorf("health status = %d, want %d", resp.StatusCode, http.StatusNoContent)
				}
			}
		})
	}
}
