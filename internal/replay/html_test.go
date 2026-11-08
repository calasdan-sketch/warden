package replay

import (
	"bytes"
	"strings"
	"testing"
)

// The HTML replay embeds recorded (attacker-influenced) text as data. It must
// never let that text close the script block or add markup.
func TestHTMLReplayEscapesHostileText(t *testing.T) {
	run, spans := fixture()
	evil := `</script><img src=x onerror=alert(1)><!-- ` + " " + `‮`
	spans[1].ArgsSummary = evil
	spans[2].PolicyReason = evil
	spans[3].Path = evil
	spans[4].Host = evil
	run.AgentID = evil
	s := Build(run, spans, Integrity{Status: "verified", Detail: evil})
	var b bytes.Buffer
	if err := s.HTML(&b); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	for _, bad := range []string{"<img src=x", "onerror=alert(1)><", "</script><img"} {
		if strings.Contains(h, bad) {
			t.Errorf("hostile markup %q reached the page", bad)
		}
	}
	if strings.Count(strings.ToLower(h), "</script>") != strings.Count(strings.ToLower(h), "<script") {
		t.Error("script tags are unbalanced: recorded text closed or opened one")
	}
	for _, r := range h {
		if r == 0x202e || r == 0x2028 {
			t.Errorf("U+%04X reached the page", r)
		}
	}
}
