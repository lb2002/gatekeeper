"""The public "point the investigator at a package" page. Everything from the model or a package is set with
textContent, never as HTML: package authors choose those strings."""

TRY_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Try Gatekeeper</title><style>
:root{--bg:#fbfbf9;--fg:#1d1d1b;--muted:#6b6b66;--line:#e3e3dd;--panel:#f3f3ee;--accent:#b4232c;--warn:#a86a00;--ok:#2c7a4b}
@media (prefers-color-scheme:dark){:root{--bg:#151514;--fg:#ececea;--muted:#9a9a94;--line:#2c2c2a;--panel:#1e1e1c;--accent:#ef6b6b;--warn:#e5ab4a;--ok:#6cc08b}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:880px;margin:0 auto;padding:24px 16px}
h1{font-size:26px;margin:0 0 6px}.sub{color:var(--muted);margin:0 0 20px}a{color:inherit}
form{display:flex;gap:8px;flex-wrap:wrap}
input{flex:1 1 260px;min-width:0;font:15px ui-monospace,Menlo,Consolas,monospace;padding:10px 12px;border:1px solid var(--line);border-radius:6px;background:transparent;color:inherit}
button{font:inherit;padding:10px 16px;border:1px solid var(--fg);border-radius:6px;background:var(--fg);color:var(--bg);cursor:pointer}
button:disabled{opacity:.5;cursor:default}
.examples{margin:10px 0 22px;color:var(--muted);font-size:14px}.examples button{background:none;color:inherit;border:0;padding:0 4px;text-decoration:underline;font-size:14px}
#steps{list-style:none;padding:0;margin:0}#steps li{padding:9px 0;border-top:1px solid var(--line)}
.tool{font:13px ui-monospace,Menlo,Consolas,monospace;font-weight:600}.why{color:var(--muted);font-size:14px}.target{font:13px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
#working{color:var(--muted);padding:10px 0}
#verdict{margin-top:18px;padding:16px;background:var(--panel);border-radius:8px;display:none}
#label{font-size:20px;font-weight:700;margin:0}.malicious{color:var(--accent)}.suspicious{color:var(--warn)}.benign{color:var(--ok)}
#summary{margin:8px 0 12px}#evidence{margin:0;padding-left:18px;font-size:14px}
#unverified{color:var(--warn);font-size:14px}#meta{color:var(--muted);font-size:13px;margin-top:10px}
pre{font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;overflow-x:auto;padding:10px;background:var(--bg);border:1px solid var(--line);border-radius:6px;margin:8px 0 0}
details{margin-top:10px}summary{cursor:pointer;font-size:14px}
#error,#auditerror{color:var(--accent);margin-top:12px}
#audit,#local{margin-top:36px;border-top:1px solid var(--line);padding-top:6px}h2{font-size:19px;margin:14px 0 4px}
textarea{display:block;width:100%;box-sizing:border-box;font:13px ui-monospace,Menlo,Consolas,monospace;padding:10px;margin:10px 0;border:1px solid var(--line);border-radius:6px;background:transparent;color:inherit}
#auditfindings{padding-left:18px;font-size:14px}.bad{color:var(--accent)}.note{color:var(--warn)}.clean{color:var(--ok)}
footer{color:var(--muted);font-size:13px;margin-top:28px}
</style></head><body>
<h1>Watch a Muse agent read an npm package</h1>
<p class=sub>Muse Spark Open opens the published archive, decides where to look, and has to cite every line it relies on.
The package is read in memory on our server and never executed.</p>
<form id=form><label for=pkg hidden>npm package</label>
<input id=pkg placeholder="name or name@version" autocomplete=off spellcheck=false maxlength=214 required>
<button id=go>Investigate</button></form>
<div class=examples>Try: <button type=button data-p="tailwind-fabric@3.0.4">tailwind-fabric</button> (reported malware, still on npm)
<button type=button data-p="left-pad">left-pad</button> <button type=button data-p="chalk">chalk</button></div>
<ol id=steps></ol><div id=working hidden>Reading the package…</div>
<div id=error role=alert></div>
<section id=verdict aria-live=polite><p id=label></p><p id=summary></p><ul id=evidence></ul><p id=unverified></p>
<details id=shown hidden><summary>What the model was shown</summary><div id=excerpts></div></details><p id=meta></p></section>
<section id=audit><h2>Is your project affected?</h2>
<p class=sub>Paste a <code>package-lock.json</code>, <code>pnpm-lock.yaml</code> or <code>yarn.lock</code>, or pick the file. We check every
locked version against reported malware and look for packages from outside the registry. Nothing is stored or installed.</p>
<input id=file type=file accept=".json,.yaml,.yml,.lock" aria-label="Lockfile">
<textarea id=lock rows=6 placeholder="Paste a lockfile" spellcheck=false aria-label="Lockfile text"></textarea>
<button id=check type=button>Check my lockfile</button>
<div id=auditerror role=alert></div><p id=auditsummary></p><ul id=auditfindings></ul></section>
<section id=local><h2>On your own machine</h2>
<p class=sub>Stop malware before <code>npm install</code> runs it, for you or your AI coding agent. No account and no GPU, under a minute:</p>
<pre>uv tool install git+https://github.com/lb2002/gatekeeper
gk guard setup
gk guard shell</pre>
<p class=sub>In your project, <code>gk audit</code> does the lockfile check above. In CI: <code>uses: lb2002/gatekeeper@v1</code>.</p></section>
<footer>A model's opinion on the package you asked about, not a finding: confirmed detections are on the
<a href="/">live page</a>. <a href="https://github.com/lb2002/gatekeeper">Source</a>. Limited to a small number of runs a day.</footer>
<script>
const $ = id => document.getElementById(id);
const said = {read: "read", search: "search", decode: "decode", strings: "strings"};
let timer = null, shown = 0;
function reset() {
  clearTimeout(timer); shown = 0;
  $("steps").textContent = ""; $("error").textContent = ""; $("evidence").textContent = ""; $("excerpts").textContent = "";
  $("unverified").textContent = ""; $("verdict").style.display = "none"; $("shown").hidden = true; $("working").hidden = true;
}
function addStep(s) {
  const li = document.createElement("li");
  const tool = document.createElement("span"); tool.className = "tool"; tool.textContent = (said[s.action] || "look") + " ";
  const target = document.createElement("span"); target.className = "target";
  target.textContent = s.action === "search" ? s.terms.join(", ") : s.path + (s.action === "read" ? " rows " + s.first_row + "-" + s.last_row : "");
  const why = document.createElement("div"); why.className = "why"; why.textContent = s.reason;
  li.append(tool, target, why); $("steps").append(li);
}
function finish(r) {
  $("working").hidden = true; $("go").disabled = false;
  if (r.error) { $("error").textContent = r.error; return; }
  const v = r.verdict;
  if (!v) { $("error").textContent = "The model gave no usable answer. Try again in a moment."; return; }
  $("label").textContent = v.verdict.toUpperCase() + " · confidence " + v.confidence.toFixed(2);
  $("label").className = v.verdict;
  $("summary").textContent = v.summary;
  for (const e of v.evidence) { const li = document.createElement("li"); li.textContent = e.excerpt_id + " lines " + e.line_start + "-" + e.line_end + ": " + e.why; $("evidence").append(li); }
  if (r.errors.length) $("unverified").textContent = "Not verified by the checker: " + r.errors.join("; ");
  for (const x of r.excerpts) { const p = document.createElement("pre"); p.textContent = x; $("excerpts").append(p); }
  $("shown").hidden = !r.excerpts.length;
  $("meta").textContent = r.steps.length + " steps, $" + r.cost_usd.toFixed(4) + " on " + r.model;
  $("verdict").style.display = "block";
}
async function poll(key) {
  let r;
  try { r = await (await fetch("/try/result?key=" + encodeURIComponent(key))).json(); } catch (e) { timer = setTimeout(() => poll(key), 2500); return; }
  for (; shown < (r.steps || []).length; shown++) addStep(r.steps[shown]);
  if (r.status === "done") finish(r); else timer = setTimeout(() => poll(key), 1500);
}
async function start(pkg) {
  reset(); $("go").disabled = true; $("working").hidden = false;
  try {
    const resp = await fetch("/try/start", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({package: pkg})});
    const r = await resp.json();
    if (!resp.ok) { finish({error: r.detail || "That did not work."}); return; }
    poll(r.key);
  } catch (e) { finish({error: "Could not reach the server."}); }
}
$("file").addEventListener("change", async e => { if (e.target.files[0]) $("lock").value = await e.target.files[0].text(); });
$("check").addEventListener("click", async () => {
  $("auditerror").textContent = ""; $("auditsummary").textContent = "Checking…"; $("auditsummary").className = ""; $("auditfindings").textContent = "";
  try {
    const resp = await fetch("/try/audit", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({lockfile: $("lock").value})});
    const r = await resp.json();
    if (!resp.ok) { $("auditsummary").textContent = ""; $("auditerror").textContent = r.detail || "That did not work."; return; }
    const bad = r.findings.length;
    $("auditsummary").textContent = r.packages + " packages checked, " + r.install_scripts + " with install scripts. " +
      (bad ? bad + " finding" + (bad > 1 ? "s" : "") + ":" : "No reported malware and no foreign sources. That covers what is known so far, not what nobody has found yet.");
    $("auditsummary").className = r.severe ? "bad" : bad ? "note" : "clean";
    for (const f of r.findings) { const li = document.createElement("li"); li.textContent = f.name + "@" + f.version + ": " + f.detail; $("auditfindings").append(li); }
  } catch (e) { $("auditsummary").textContent = ""; $("auditerror").textContent = "Could not reach the server."; }
});
$("form").addEventListener("submit", e => { e.preventDefault(); start($("pkg").value.trim()); });
document.querySelectorAll("[data-p]").forEach(b => b.addEventListener("click", () => { $("pkg").value = b.dataset.p; start(b.dataset.p); }));
</script></body></html>
"""
