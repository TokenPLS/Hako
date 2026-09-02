package hako

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/dns"
	"github.com/TokenPLS/Hako/hub/route"

	D "github.com/miekg/dns"
)

// The reader's question is "why does this name resolve there", and /dns/query cannot answer
// it: upstream returns the DNS message and nothing about how it was obtained
// (hub/route/dns.go:50-58). This lives in Hako's own namespace rather than extending that
// route, so upstream's tree is untouched and there is no shape for a dashboard to notice.
func init() {
	route.Register(func(router chi.Router) {
		router.Get("/hako/v1/dns/explain", serveDNSExplain)
	})
}

// probeRequested reads the opt-in. Default off: the explanation is computed from pure
// functions and sends nothing, so a reader can press the button as often as they like. Only
// probe=1 spends a query, and only then is there a winner to name.
func probeRequested(request *http.Request) bool {
	raw := strings.TrimSpace(request.URL.Query().Get("probe"))
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
}

// explainableResolver digs the resolver that answers ordinary queries out of whatever the
// process installed as the default.
//
// A running core holds a dns.Resolvers VALUE: hub/executor/executor.go:335 assigns what
// dns.NewResolver returns (dns/resolver.go:581), and Resolvers embeds *Resolver rather
// than being one. Embedding is not identity — a type assertion compares the dynamic type
// exactly — so asserting *dns.Resolver alone reports "DNS is not running" on every core
// where DNS is running. Both shapes are accepted because NewResolverFromClient still
// hands out a bare *Resolver.
//
// The embedded Resolver is the right one to explain: its siblings are installed into
// separate globals for separate jobs (ProxyServerHostResolver, DirectHostResolver at
// executor.go:341,347), and neither answers the ordinary query a reader is asking about.
func explainableResolver(installed any) *dns.Resolver {
	switch actual := installed.(type) {
	case dns.Resolvers:
		return actual.Resolver
	case *dns.Resolvers:
		if actual == nil {
			return nil
		}
		return actual.Resolver
	case *dns.Resolver:
		return actual
	default:
		return nil
	}
}

type dnsExplainResponse struct {
	Domain      string   `json:"domain"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	MatchedRule string   `json:"matchedRule,omitempty"`
	Candidates  []string `json:"candidates"`
	// Present only when a probe ran. The asymmetry is deliberate: it says outright
	// whether a query happened, rather than leaving a reader to guess from an empty
	// answer section.
	AnsweredBy string   `json:"answeredBy,omitempty"`
	Answer     []string `json:"answer,omitempty"`
	Probed     bool     `json:"probed"`
	Cache      *struct {
		Hit bool `json:"hit"`
		// ExpiresAt may be in the PAST: since an expired entry is served anyway
		// (TTL 1, refresh behind it), so the client is expected to render "expired N
		// ago, still in use" rather than a negative countdown.
		ExpiresAt string `json:"expiresAt"`
		Stale     bool   `json:"stale"`
	} `json:"cache,omitempty"`
}

func serveDNSExplain(writer http.ResponseWriter, request *http.Request) {
	domain := strings.TrimSpace(request.URL.Query().Get("domain"))
	if domain == "" {
		writeExplainError(writer, http.StatusBadRequest, "domain is required")
		return
	}
	// A resolver that does not exist is a different answer from one that matched nothing,
	// and a reader debugging their DNS is exactly the person who needs to be told which.
	live := explainableResolver(resolver.DefaultResolver)
	if live == nil {
		writeExplainError(writer, http.StatusServiceUnavailable,
			"DNS is not running in this core, so there is no resolution to explain")
		return
	}

	// Upstream's own table, not a list kept here.
	//
	// A hand-kept list of four shipped refusing MX, NS, SRV and PTR while /dns/query --
	// the other endpoint on the same screen -- answered all of them, so the route section
	// silently vanished for half the picker. The whitelist was not protecting a
	// distinction that exists: isIPRequest is A, AAAA and CNAME (dns/util.go:124) and
	// every other type falls to the same matchPolicy and the same batchExchange
	// (dns/resolver.go:270), so what this reports for TXT is exactly what it would report
	// for MX. Reading the same map upstream reads (hub/route/dns.go:32) makes the two
	// agree by construction rather than by somebody remembering to extend a list.
	raw := strings.ToUpper(strings.TrimSpace(request.URL.Query().Get("type")))
	qType := D.TypeA
	if raw != "" {
		known, exists := D.StringToType[raw]
		if !exists {
			writeExplainError(writer, http.StatusBadRequest, "invalid query type")
			return
		}
		qType = known
	}

	question := new(D.Msg)
	question.SetQuestion(D.Fqdn(domain), qType)
	probe := probeRequested(request)
	explanation := live.Explain(request.Context(), question, probe)

	response := dnsExplainResponse{
		Domain:      domain,
		Type:        D.TypeToString[qType],
		Source:      explanation.Source,
		MatchedRule: explanation.MatchedRule,
		Candidates:  explanation.Candidates,
		AnsweredBy:  explanation.AnsweredBy,
		Probed:      probe,
	}
	if response.Candidates == nil {
		response.Candidates = []string{}
	}
	if explanation.Answer != nil {
		for _, record := range explanation.Answer.Answer {
			response.Answer = append(response.Answer, record.String())
		}
	}
	if explanation.CacheExpiresAt != nil {
		response.Cache = &struct {
			Hit       bool   `json:"hit"`
			ExpiresAt string `json:"expiresAt"`
			Stale     bool   `json:"stale"`
		}{
			Hit:       true,
			ExpiresAt: explanation.CacheExpiresAt.Format(time.RFC3339),
			Stale:     explanation.CacheStale,
		}
	}
	writeSnapshotJSON(writer, response)
}

func writeExplainError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"message": message})
}
