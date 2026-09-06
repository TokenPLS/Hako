package outboundgroup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/adapter/outbound"
	"github.com/TokenPLS/Hako/adapter/provider"
	"github.com/TokenPLS/Hako/common/utils"
	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
)

func groupOfDirect(t *testing.T) *GroupBase {
	t.Helper()
	compatible, err := provider.NewCompatibleProvider("members", []C.Proxy{adapter.NewProxy(outbound.NewDirect())}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewGroupBase(GroupBaseOption{Name: "g", Type: C.URLTest, Providers: []P.ProxyProvider{compatible}})
}

// The group endpoint reads the outcome the same way the single-proxy one
// does: with `expected`, a member whose answer falls outside it is not a
// success; without `expected`, any answer is.
func TestAGroupDelayTreatsAnUnexpectedStatusAsAFailureWhenExpectedIsGiven(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	expected, err := utils.NewUnsignedRanges[uint16]("200-299")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	delays, err := groupOfDirect(t).URLTest(ctx, server.URL, expected)
	if err == nil || len(delays) != 0 {
		t.Fatalf("with expected=200-299 a 503 member is a failure, got %v, %v", delays, err)
	}
	delays, err = groupOfDirect(t).URLTest(ctx, server.URL, nil)
	if err != nil || delays["DIRECT"] == 0 {
		t.Fatalf("without expected any answer counts, got %v, %v", delays, err)
	}
}
