package policy

import (
	"testing"

	"github.com/calasdan-sketch/warden/internal/model"
)

// Windows-style paths (backslashes, drive letters, UNC shares) must be judged
// like their Unix equivalents. This is a static check that runs on any OS; it
// does not replace a run on a real Windows host.
func TestWindowsStylePathsAreJudged(t *testing.T) {
	p, _ := Default()
	e := NewEvaluator(p, nil)
	for _, path := range []string{
		`C:\Users\me\.aws\credentials`, `C:\Users\me\.ssh\id_rsa`, `C:/Users/me/.ssh/id_rsa`,
		`\\server\share\.env`, `..\..\.env`,
		`C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Login Data`,
	} {
		if d := e.Evaluate(&model.Span{Kind: model.SpanFileOp, Op: "read", Path: path}).Decision; d == Allow {
			t.Errorf("file read of %s was allowed", path)
		}
	}
	for _, c := range []string{`type C:\Users\me\.aws\credentials`, `cat C:\Users\me\.ssh\id_rsa`, `cat ~\.ssh\id_rsa`} {
		if d := e.Evaluate(&model.Span{Kind: model.SpanToolCall, Tool: "Bash", ArgsSummary: c}).Decision; d == Allow {
			t.Errorf("%q was allowed", c)
		}
	}
	if d := e.Evaluate(&model.Span{Kind: model.SpanFileOp, Op: "write", Path: `C:\Users\me\.warden\receipt.key`}).Decision; d != Deny {
		t.Errorf("writing warden's own key from a Windows path must be denied, got %v", d)
	}
}
