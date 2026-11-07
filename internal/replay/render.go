package replay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"text/tabwriter"
)

var verdictLabel = map[string]string{"allow": "allow", "deny": "DENY", "ask": "ASK", "ok": "ok", "error": "ERROR"}

// Text writes the timeline. onlyGated limits it to denied/ask/error steps.
func (s *Session) Text(w io.Writer, onlyGated bool) {
	r := s.Run
	fmt.Fprintf(w, "run %s  agent=%s fleet=%s  status=%s\n", Clean(r.RunID, 64), Clean(r.AgentID, 40), Clean(r.FleetID, 40), r.Status)
	fmt.Fprintf(w, "started %s  duration %s  calls=%d cost=$%.4f\n", r.StartedAt.UTC().Format("2006-01-02 15:04:05Z"), s.Duration().Round(100e6), r.ToolCalls, r.CostUSD)
	if r.KillReason != nil {
		by := ""
		if r.KilledBy != nil {
			by = " by " + Clean(*r.KilledBy, 40)
		}
		fmt.Fprintf(w, "killed%s: %s\n", by, Clean(*r.KillReason, 160))
	}
	fmt.Fprintf(w, "integrity: %s - %s\n\n", strings.ToUpper(s.Integrity.Status), Clean(s.Integrity.Detail, 200))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	hdr := "#\t+t\tkind\twhat\tverdict"
	if s.WhatIf != nil {
		hdr += "\tif " + s.WhatIf.Policy
	}
	fmt.Fprintln(tw, hdr)
	for _, st := range s.Steps {
		if onlyGated && (st.Verdict == "allow" || st.Verdict == "ok") && (st.WhatIf == nil || !st.WhatIf.Changed) {
			continue
		}
		line := fmt.Sprintf("%d\t+%.1fs\t%s\t%s\t%s", st.N, float64(st.OffsetMs)/1000, st.Span.Kind, st.What, verdictLabel[st.Verdict])
		if s.WhatIf != nil {
			cell := ""
			if st.WhatIf != nil {
				switch {
				case st.WhatIf.Skipped != "":
					cell = "n/a"
				case st.WhatIf.Changed:
					cell = "CHANGES -> " + verdictLabel[st.WhatIf.Decision]
				default:
					cell = "same"
				}
			}
			line += "\t" + cell
		}
		fmt.Fprintln(tw, line)
	}
	tw.Flush()
	if f := s.WhatIf; f != nil {
		fmt.Fprintf(w, "\nwhat-if %q over %d gated calls: %d newly blocked, %d newly allowed, %d unchanged, %d not replayable\n",
			f.Policy, f.Evaluated, f.NewlyBlocked, f.NewlyAllowed, f.Unchanged, f.SkippedNonPure)
	}
}

// Step prints the full state at step n with a little context around it.
func (s *Session) Step(w io.Writer, n int) error {
	if n < 1 || n > len(s.Steps) {
		return fmt.Errorf("step %d out of range 1..%d", n, len(s.Steps))
	}
	st := s.Steps[n-1]
	sp := st.Span
	fmt.Fprintf(w, "step %d of %d  (+%.1fs)  %s  verdict=%s\n", st.N, len(s.Steps), float64(st.OffsetMs)/1000, sp.Kind, verdictLabel[st.Verdict])
	fmt.Fprintf(w, "integrity: %s\n", strings.ToUpper(s.Integrity.Status))
	if sp.LateAfterSeal {
		fmt.Fprintln(w, "WARNING: recorded after the receipt was sealed; NOT covered by the signature")
	}
	fmt.Fprintf(w, "what:      %s\n", st.What)
	if sp.PolicyDecision != "" {
		fmt.Fprintf(w, "policy:    %s (v%s) %s\n", sp.PolicyDecision, Clean(sp.PolicyVersion, 10), Clean(sp.PolicyReason, 300))
	}
	if sp.ToolCallID != "" {
		fmt.Fprintf(w, "call id:   %s\n", Clean(sp.ToolCallID, 80))
	}
	if sp.Redacted {
		fmt.Fprintln(w, "note:      secrets were redacted from this span before storage")
	}
	if st.WhatIf != nil && st.WhatIf.Skipped == "" {
		fmt.Fprintf(w, "what-if:   %s %s\n", verdictLabel[st.WhatIf.Decision], st.WhatIf.Reason)
	}
	state := s.StateAt(n)
	fmt.Fprintf(w, "\nstate after this step\n  tool calls %d, denied %d, asked %d\n  tokens in/out %d/%d, cost $%.4f\n", state.ToolCalls, state.Denied, state.Asked, state.TokensIn, state.TokensOut, state.CostUSD)
	fmt.Fprintf(w, "  tools used (%d): %s\n  files touched (%d): %s\n  hosts contacted (%d): %s\n",
		state.ToolsN, strings.Join(state.Tools, ", "), state.FilesN, strings.Join(state.Files, ", "), state.HostsN, strings.Join(state.Hosts, ", "))
	fmt.Fprintln(w, "\ncontext")
	for i := n - 4; i <= n; i++ {
		if i < 0 || i >= len(s.Steps) {
			continue
		}
		c := s.Steps[i]
		mark := " "
		if c.N == n {
			mark = ">"
		}
		fmt.Fprintf(w, "%s %3d +%.1fs %-12s %-5s %s\n", mark, c.N, float64(c.OffsetMs)/1000, c.Span.Kind, verdictLabel[c.Verdict], c.What)
	}
	return nil
}

// JSON writes the session as indented JSON.
func (s *Session) JSON(w io.Writer) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(s)
}

// HTML writes one self-contained page (no network, no external assets) with
// keyboard stepping. All trail text is escaped; the data is embedded as
// HTML-safe JSON and rendered with textContent only.
func (s *Session) HTML(w io.Writer) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(s); err != nil {
		return err
	}
	data := strings.NewReplacer(" ", ` `, " ", ` `).Replace(buf.String())
	fmt.Fprintf(w, htmlHead, html.EscapeString(Clean(s.Run.RunID, 64)))
	fmt.Fprintf(w, "<script id=\"d\" type=\"application/json\">%s</script>", data)
	_, err := io.WriteString(w, htmlTail)
	return err
}

const htmlHead = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>warden replay %s</title>
<style>
:root{--bg:#fff;--fg:#14171a;--mut:#5b6670;--line:#d9dee3;--deny:#b42318;--ask:#b54708;--ok:#067647;--sel:#e8f0fe}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e6e9ec;--mut:#98a2ab;--line:#2a323a;--deny:#ff8a80;--ask:#ffb74d;--ok:#6fd39b;--sel:#1c2a44}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
header{padding:12px 16px;border-bottom:1px solid var(--line)}
h1{font-size:16px;margin:0 0 4px}.mut{color:var(--mut)}
.bar{padding:8px 16px;display:flex;gap:12px;align-items:center;border-bottom:1px solid var(--line);flex-wrap:wrap}
main{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);gap:0}
@media (max-width:800px){main{grid-template-columns:1fr}}
#list{overflow:auto;max-height:78vh;border-right:1px solid var(--line)}
.row{display:grid;grid-template-columns:44px 64px 90px minmax(0,1fr) 56px;gap:8px;padding:5px 12px;border-bottom:1px solid var(--line);cursor:pointer;font-family:ui-monospace,Menlo,monospace;font-size:12px}
.row.sel{background:var(--sel)}.row span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.v-deny{color:var(--deny);font-weight:700}.v-ask{color:var(--ask);font-weight:700}.v-error{color:var(--deny)}.v-allow,.v-ok{color:var(--ok)}
#detail{padding:12px 16px;overflow:auto;max-height:78vh}
pre{white-space:pre-wrap;word-break:break-word;background:transparent;margin:0}
.badge{padding:2px 8px;border-radius:10px;border:1px solid var(--line);font-weight:600}
button,label{font:inherit}
</style></head><body>
<header><h1 id="t"></h1><div id="sub" class="mut"></div></header>
<div class="bar"><span id="integ" class="badge"></span><label><input type="checkbox" id="gated"> only denied / asked / error</label><span class="mut">keys: j/k or arrows step, g first, G last</span></div>
<main><div id="list"></div><div id="detail"></div></main>
`

const htmlTail = `
<script>
(function(){
var S=JSON.parse(document.getElementById('d').textContent);
var cur=0,gated=false;
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
var R=S.run;
document.getElementById('t').textContent='run '+R.run_id+'  ['+R.status+']';
document.getElementById('sub').textContent='agent '+R.agent_id+' / fleet '+R.fleet_id+' / started '+R.started_at+' / '+S.steps.length+' steps';
var ib=document.getElementById('integ');ib.textContent='integrity: '+S.integrity.status.toUpperCase();ib.title=S.integrity.detail;
ib.style.color=S.integrity.status==='verified'?'var(--ok)':'var(--deny)';
function vis(){return S.steps.filter(function(s){return !gated||(s.verdict!=='allow'&&s.verdict!=='ok')||(s.what_if&&s.what_if.changed)})}
var WIN=400;
function lists(n){
 var st=S.steps[n].state;
 if(st.files_touched||(st.files_count+st.hosts_count+st.tools_count===0))return st;
 var f={},h={},t={};
 for(var i=0;i<=n;i++){var x=S.steps[i].span;
  if(x.kind==='tool.call'&&x.tool)t[x.tool]=1;
  if(x.kind==='file.op'&&x.path)f[x.path]=1;
  if(x.kind==='net.egress'&&x.host)h[x.host]=1}
 function top(m,c){var k=Object.keys(m).sort();var r=k.slice(0,50);if(k.length>50)r.push('… +'+(k.length-50)+' more');return r}
 var o={};for(var k in st)o[k]=st[k];
 o.files_touched=top(f);o.hosts_contacted=top(h);o.tools_used=top(t);return o}
function draw(){
 var L=document.getElementById('list');L.textContent='';
 var all=vis(),ci=0;for(var q=0;q<all.length;q++){if(all[q].n-1===cur){ci=q;break}}
 var lo=Math.max(0,ci-WIN/4),hi=Math.min(all.length,lo+WIN);
 if(lo>0){L.appendChild(el('div','mut','… '+lo+' earlier steps (use k / g to move)'))}
 all.slice(lo,hi).forEach(function(s){
  var r=el('div','row'+(s.n-1===cur?' sel':''));
  r.appendChild(el('span','mut',String(s.n)));
  r.appendChild(el('span','mut','+'+(s.offset_ms/1000).toFixed(1)+'s'));
  r.appendChild(el('span','',s.span.kind));
  r.appendChild(el('span','',s.what));
  r.appendChild(el('span','v-'+s.verdict,s.verdict.toUpperCase()));
  r.onclick=function(){cur=s.n-1;draw()};L.appendChild(r)});
 if(hi<all.length){L.appendChild(el('div','mut','… '+(all.length-hi)+' later steps (use j / G to move)'))}
 var s=S.steps[cur];var D=document.getElementById('detail');D.textContent='';
 if(!s){D.textContent='no steps';return}
 D.appendChild(el('h2','', 'step '+s.n+' of '+S.steps.length));
 var p=el('pre');
 var lines=['kind: '+s.span.kind,'verdict: '+s.verdict,'what: '+s.what];
 if(s.span.policy_decision)lines.push('policy: '+s.span.policy_decision+' '+(s.span.policy_reason||''));
 if(s.span.late_after_seal)lines.push('WARNING: recorded after seal, not covered by the signature');
 if(s.what_if&&!s.what_if.skipped)lines.push('what-if: '+s.what_if.decision+(s.what_if.changed?'  (CHANGES)':'')+' '+(s.what_if.reason||''));
 var st=lists(cur);lines.push('','after this step:','  calls '+st.tool_calls+', denied '+st.denied+', asked '+st.asked,'  tokens '+st.tokens_in+'/'+st.tokens_out+', cost $'+st.cost_usd.toFixed(4),'  tools: '+(st.tools_used||[]).join(', '),'  files ('+(st.files_count||0)+'): '+(st.files_touched||[]).join(', '),'  hosts ('+(st.hosts_count||0)+'): '+(st.hosts_contacted||[]).join(', '));
 p.textContent=lines.join('\n');D.appendChild(p);
}
function move(d){var v=vis();if(!v.length)return;var i=0;for(var k=0;k<v.length;k++){if(v[k].n-1===cur)i=k}
 i=Math.max(0,Math.min(v.length-1,i+d));cur=v[i].n-1;draw();var sel=document.querySelector('.row.sel');if(sel)sel.scrollIntoView({block:'nearest'})}
document.getElementById('gated').onchange=function(e){gated=e.target.checked;var v=vis();if(v.length)cur=v[0].n-1;draw()};
document.addEventListener('keydown',function(e){
 if(e.key==='j'||e.key==='ArrowDown'){move(1);e.preventDefault()}
 else if(e.key==='k'||e.key==='ArrowUp'){move(-1);e.preventDefault()}
 else if(e.key==='g'){cur=0;draw()}else if(e.key==='G'){cur=S.steps.length-1;draw()}});
draw();
})();
</script></body></html>
`
