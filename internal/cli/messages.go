package cli

import (
	"context"
	"flag"
	"fmt"
	"net/netip"

	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/trace"
)

type messagesOpts struct {
	unique bool
	count  bool
}

func init() {
	Register(NewCommand(Command{
		Name:    "messages",
		Group:   "Inspect",
		Aliases: []string{"search", "grep"},
		Summary: "list the SIP messages matching the filters, one row each",
		Usage:   "messages [flags] CAPTURE...",
	}, func(fs *flag.FlagSet, o *messagesOpts) {
		fs.BoolVar(&o.unique, "unique", false, "only the first matching message of every Call-ID")
		fs.BoolVar(&o.count, "count", false, "print only the number of matching messages")
	}, runMessages))
}

func runMessages(ctx context.Context, env *Env, c *Common, o *messagesOpts) int {
	q, err := c.Query()
	if err != nil {
		return env.Fail(err)
	}
	ds, err := c.Open(ctx, env, func(opt *engine.Options) { opt.RTP = opt.RTP && q.NeedsCalls() })
	if err != nil {
		return env.Fail(err)
	}
	idx, err := Select(ctx, ds, q, 0)
	if err != nil {
		return env.Fail(err)
	}
	if o.unique {
		seen := make(map[string]bool, len(idx))
		kept := idx[:0]
		for _, i := range idx {
			id := ds.Messages[i].CallID
			if !seen[id] {
				seen[id] = true
				kept = append(kept, i)
			}
		}
		idx = kept
	}
	if o.count {
		_, err := fmt.Fprintln(env.Stdout, len(idx))
		return env.Fail(err)
	}
	t := MessageTable(ds.Messages, idx)
	c.Infof(env, "%s matched", plural(len(idx), "message"))
	return env.Fail(c.WriteTable(env, t))
}

// MessageTable renders msgs[i] for every i in idx: Timestamp, Info, Call-ID,
// From and To, plus the extra columns Src, Dst, Contact, URI, File#Index and UA.
func MessageTable(msgs []trace.Message, idx []int) report.Table {
	t := report.Table{
		Title: "SIP messages",
		Columns: []report.Column{
			{Name: "Timestamp", Key: "timestamp", Kind: report.Time},
			{Name: "Info", Key: "info", Kind: report.String, Style: infoStyle},
			{Name: "Call-ID", Key: "call_id", Kind: report.String},
			{Name: "From", Key: "from", Kind: report.String},
			{Name: "To", Key: "to", Kind: report.String},
			{Name: "Src", Key: "src", Kind: report.String, Extra: true},
			{Name: "Dst", Key: "dst", Kind: report.String, Extra: true},
			{Name: "Contact", Key: "contact", Kind: report.String, Extra: true},
			{Name: "URI", Key: "uri", Kind: report.String, Extra: true},
			{Name: "File#Index", Key: "file_index", Kind: report.String, Extra: true},
			{Name: "UA", Key: "ua", Kind: report.String, Extra: true},
		},
		Rows: make([][]any, 0, len(idx)),
	}
	for _, i := range idx {
		m := &msgs[i]
		t.Rows = append(t.Rows, []any{
			m.Time, m.Info(), m.CallID, m.From, m.To,
			endpoint(m.Src, m.SrcPort), endpoint(m.Dst, m.DstPort), m.Contact, m.RequestURI,
			fmt.Sprintf("%s#%d", m.File, m.Index), userAgent(m),
		})
	}
	return t
}

func endpoint(a netip.Addr, port uint16) string {
	if !a.IsValid() {
		return ""
	}
	return netip.AddrPortFrom(a, port).String()
}

// userAgent is the User-Agent of a request or the Server of a response, falling
// back to the other header.
func userAgent(m *trace.Message) string {
	first, second := "User-Agent", "Server"
	if !m.IsRequest {
		first, second = second, first
	}
	if v := m.Header(first); v != "" {
		return v
	}
	return m.Header(second)
}

// infoStyle colours responses by class; requests stay plain.
func infoStyle(v any) report.Style {
	s, _ := v.(string)
	if code, ok := leadingInt(s); ok {
		return report.StatusStyle(code)
	}
	return report.None
}

func leadingInt(s string) (int, bool) {
	n, i := 0, 0
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n, i == 3 && (len(s) == 3 || s[3] == ' ')
}
