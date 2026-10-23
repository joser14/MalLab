"""A professional, self-contained HTML malware analysis report for a case.

One standalone HTML file (inline CSS, no external requests) that prints cleanly to PDF and reads
like a commercial sandbox report: executive summary with the verdict up top, then per-sample
static and dynamic findings, detections mapped to ATT&CK, consolidated IOCs, and recommended
actions. Pure string building over the dicts the service gathers — no I/O here.
"""

import html
import time

_SEV_COLOR = {"high": "#dc2f4a", "medium": "#b8710a", "low": "#2f5bff", "info": "#6a6791"}
_VERDICT_COLOR = {"malicious": "#dc2f4a", "suspicious": "#b8710a", "clean": "#0f9468", "unknown": "#6a6791"}


def _e(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _chiplist(items, cls="chip"):
    items = [i for i in (items or []) if i]
    if not items:
        return '<span class="muted">None</span>'
    return "".join(f'<span class="{cls}">{_e(i)}</span>' for i in items[:60])


def _codelist(items):
    items = [i for i in (items or []) if i]
    return "<pre>" + _e("\n".join(items)) + "</pre>" if items else '<span class="muted">None</span>'


def _verdict_pill(v: dict) -> str:
    col = _VERDICT_COLOR.get(v.get("verdict", "unknown"), "#6a6791")
    fam = f' · {_e(v["family"])}' if v.get("family") else ""
    return (f'<span class="pill" style="background:{col}">{_e(v.get("verdict", "unknown").upper())}</span>'
            f'<span class="score">{v.get("score", 0)}/100</span>'
            f'<span class="muted">{_e(v.get("confidence", "low"))} confidence{fam}</span>')


def _summary_sentence(case_verdict: dict, n: int) -> str:
    verdict = case_verdict.get("verdict", "unknown")
    fams = case_verdict.get("families") or []
    famtxt = f" The activity is consistent with {_e(', '.join(fams[:3]))}." if fams else ""
    base = {
        "malicious": f"Analysis of {n} sample(s) found behaviour and indicators consistent with malware.",
        "suspicious": f"Analysis of {n} sample(s) found suspicious characteristics that warrant further review.",
        "clean": f"Analysis of {n} sample(s) did not find malicious behaviour; threat intelligence reports them clean.",
        "unknown": f"Analysis of {n} sample(s) did not gather enough signal for a confident verdict; "
                   "consider detonating, enabling more tools, or submitting to threat intel.",
    }[verdict]
    return base + famtxt


def build(case: dict, samples: list[dict], per_sample: list[dict], iocs: dict,
          case_verdict: dict) -> str:
    """per_sample: [{sample, verdict, static, detections, runs:[dynamic...]}] aligned with samples."""
    when = time.strftime("%Y-%m-%d %H:%M %Z")
    parts = [_HEAD.replace("{title}", _e(case.get("name", "Case")))]
    parts.append(f'<h1>Malware Analysis Report</h1>')
    parts.append(f'<div class="sub">{_e(case.get("name", ""))} · generated {_e(when)} · MalLab</div>')

    # Executive summary
    parts.append('<section class="exec"><h2>Executive summary</h2>')
    parts.append(f'<div class="verdictline">{_verdict_pill(case_verdict)}</div>')
    parts.append(f'<p>{_summary_sentence(case_verdict, len(samples))}</p>')
    if case.get("description"):
        parts.append(f'<p class="muted">{_e(case["description"])}</p>')
    # count detections across samples
    allfams = case_verdict.get("families") or []
    if allfams:
        parts.append(f'<p><b>Families / leads:</b> {_chiplist(allfams)}</p>')
    attck = sorted({t for ps in per_sample for t in (ps["detections"].get("attck") or [])})
    if attck:
        parts.append('<p><b>ATT&CK techniques:</b> '
                     + "".join(f'<a class="chip" href="https://attack.mitre.org/techniques/{_e(t.replace(".", "/"))}/">{_e(t)}</a>'
                               for t in attck) + '</p>')
    parts.append('</section>')

    # Per sample
    for s, ps in zip(samples, per_sample):
        st = ps["static"] or {}
        det = ps["detections"] or {}
        v = ps["verdict"] or {}
        pe = st.get("pe") or {}
        parts.append(f'<section class="sample"><h2>{_e(s["filename"])}</h2>')
        parts.append(f'<div class="verdictline">{_verdict_pill(v)}</div>')
        if v.get("reasons"):
            parts.append(f'<p class="muted">{_e(" · ".join(v["reasons"]))}</p>')
        # file facts
        rows = [("SHA-256", s.get("sha256")), ("SHA-1", s.get("sha1")), ("MD5", s.get("md5")),
                ("Type", f'{s.get("file_type") or "unknown"} · {s.get("size", 0):,} bytes · entropy {st.get("entropy", "?")}'),
                ("Source", s.get("source")), ("imphash", pe.get("imphash")),
                ("Labels", s.get("labels"))]
        parts.append('<table class="kv">' + "".join(
            f'<tr><td class="k">{_e(k)}</td><td class="mono">{_e(val)}</td></tr>'
            for k, val in rows if val) + '</table>')

        if det.get("detections"):
            parts.append('<h3>Detections</h3><table class="dets"><tr><th>Severity</th><th>Detection</th><th>ATT&CK</th><th>Evidence</th></tr>')
            for d in det["detections"]:
                col = _SEV_COLOR.get(d.get("severity"), "#6a6791")
                ev = "; ".join(d.get("evidence") or [])[:300]
                parts.append(f'<tr><td><span class="sev" style="color:{col}">{_e(d.get("severity", ""))}</span></td>'
                             f'<td><b>{_e(d.get("name"))}</b><div class="muted">{_e(d.get("description"))}</div></td>'
                             f'<td class="mono">{_e(", ".join(d.get("attck") or []))}</td>'
                             f'<td class="mono small">{_e(ev)}</td></tr>')
            parts.append('</table>')

        # static highlights
        if pe.get("suspicious_imports"):
            parts.append(f'<h3>Notable imports</h3><p>{_chiplist(pe["suspicious_imports"][:30])}</p>')
        macros = st.get("office_macros") or {}
        if macros.get("has_macros"):
            parts.append(f'<h3>Office macros</h3><p>{"Auto-executing: " + _e(", ".join(macros.get("autoexec") or [])) if macros.get("autoexec") else "VBA macros present."}</p>')
        yara = (st.get("yara") or {}).get("matches") or []
        if yara:
            parts.append(f'<h3>YARA</h3><p>{_chiplist([m["rule"] for m in yara])}</p>')

        # dynamic runs
        for dyn in ps["runs"]:
            kind = "Host observation" if dyn.get("host_observation") else "Detonation"
            parts.append(f'<h3>{kind}</h3><p><b>{_e(dyn.get("verdict", ""))}</b></p>')
            beh = dyn.get("behavior") or {}
            if dyn.get("new_runkeys") or dyn.get("new_tasks") or dyn.get("new_services"):
                parts.append('<p><b>Persistence:</b> ' + _chiplist(
                    (dyn.get("new_runkeys") or []) + [f"task: {t}" for t in dyn.get("new_tasks") or []]
                    + [f"service: {x}" for x in dyn.get("new_services") or []]) + '</p>')
            if dyn.get("network") or (beh.get("network")):
                eps = list(dyn.get("network") or []) + [f'{n.get("dst_host") or n.get("dst_ip")}:{n.get("dst_port")}' for n in beh.get("network") or []]
                parts.append(f'<p><b>Network:</b> {_chiplist(eps)}</p>')
            if dyn.get("memory"):
                parts.append('<p><b>Memory implants:</b> ' + _chiplist(
                    [f'{(m.get("image") or "").split(chr(92))[-1]} ({", ".join(k for k, val in (m.get("modified") or {}).items() if val)})' for m in dyn["memory"]]) + '</p>')
            if dyn.get("dropped"):
                parts.append('<h4>Dropped / collected files</h4><pre>' + _e("\n".join(
                    f'{d["path"]}  {d["sha256"]}' for d in dyn["dropped"])) + '</pre>')
        if s.get("notes"):
            parts.append(f'<h3>Analyst notes</h3><p class="notes">{_e(s["notes"])}</p>')
        parts.append('</section>')

    # Consolidated IOCs
    parts.append('<section class="iocs"><h2>Indicators of compromise</h2>')
    for label, key in [("URLs", "urls"), ("IP addresses", "ips"), ("Domains", "domains")]:
        if iocs.get(key):
            parts.append(f'<h3>{label}</h3>{_codelist(iocs[key])}')
    parts.append('<h3>File hashes</h3><table class="dets"><tr><th>File</th><th>SHA-256</th></tr>')
    for h in iocs.get("hashes", []):
        parts.append(f'<tr><td>{_e(h["filename"])}</td><td class="mono small">{_e(h["sha256"])}</td></tr>')
    parts.append('</table></section>')

    # Recommendations
    parts.append('<section class="rec"><h2>Recommended actions</h2><ul>')
    cv = case_verdict.get("verdict")
    if cv in ("malicious", "suspicious"):
        parts.append('<li>Block the URLs, domains and IPs above at the proxy, firewall and DNS.</li>')
        parts.append('<li>Add the file hashes to EDR/AV blocklists and hunt for them across the estate.</li>')
        parts.append('<li>Deploy the YARA and Sigma detections from this analysis to your detection pipeline.</li>')
        if any((ps["verdict"] or {}).get("family") for ps in per_sample):
            parts.append('<li>Review threat-intel reporting for the named family/families to anticipate further stages.</li>')
        parts.append('<li>If any indicator was seen in your environment, treat affected hosts as compromised and begin incident response.</li>')
    else:
        parts.append('<li>No action required on current evidence. Re-analyse with detonation and threat-intel enabled if the file remains of concern.</li>')
    parts.append('</ul></section>')

    parts.append('<footer>Generated by MalLab. A defensive analysis aid — verify findings before acting. '
                 'Verdicts are heuristic, derived from static analysis, sandbox behaviour and open threat intelligence.</footer>')
    parts.append('</div></body></html>')
    return "".join(parts)


_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title} — MalLab report</title>
<style>
  :root { --ink:#15132e; --muted:#6a6791; --line:#e2e3f2; --blue:#2f5bff; --violet:#7a3cf0; }
  * { box-sizing:border-box; }
  body { margin:0; background:#f3f4fb; color:var(--ink); font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap { max-width:900px; margin:0 auto; padding:40px 32px 80px; background:#fff; min-height:100vh; box-shadow:0 0 40px rgba(60,50,160,.06); }
  h1 { font-size:28px; margin:0 0 4px; letter-spacing:-.02em; }
  h2 { font-size:19px; margin:34px 0 12px; padding-bottom:8px; border-bottom:2px solid; border-image:linear-gradient(90deg,var(--blue),var(--violet)) 1; }
  h3 { font-size:14px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin:18px 0 8px; }
  h4 { font-size:13px; margin:12px 0 6px; }
  .sub { color:var(--muted); font-size:13px; margin-bottom:8px; }
  section { margin-top:10px; }
  .exec { background:#f6f6fd; border:1px solid var(--line); border-radius:12px; padding:18px 22px; margin-top:20px; }
  .sample { border:1px solid var(--line); border-radius:12px; padding:18px 22px; margin-top:20px; page-break-inside:avoid; }
  .verdictline { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin:6px 0 10px; }
  .pill { color:#fff; font-weight:700; font-size:12px; letter-spacing:.08em; padding:4px 10px; border-radius:6px; }
  .score { font-weight:700; font-size:18px; } .muted { color:var(--muted); }
  .chip { display:inline-block; background:#eef0fc; border:1px solid var(--line); border-radius:5px; padding:1px 8px; margin:2px 4px 2px 0; font:12px ui-monospace,Consolas,monospace; color:#3e3b60; text-decoration:none; }
  table { width:100%; border-collapse:collapse; margin:8px 0; }
  table.kv td { padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  table.kv .k { color:var(--muted); width:110px; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  table.dets th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); border-bottom:2px solid var(--line); padding:6px 8px; }
  table.dets td { padding:8px; border-bottom:1px solid var(--line); vertical-align:top; }
  .sev { font-weight:700; text-transform:uppercase; font-size:11px; }
  .mono { font-family:ui-monospace,Consolas,monospace; word-break:break-all; } .small { font-size:12px; }
  pre { background:#f6f5fe; border:1px solid var(--line); border-radius:7px; padding:10px 12px; font:12px ui-monospace,Consolas,monospace; white-space:pre-wrap; word-break:break-all; overflow:auto; }
  .notes { white-space:pre-wrap; background:#fffdf3; border-left:3px solid #b8710a; padding:8px 12px; }
  .rec ul { padding-left:20px; } .rec li { margin:5px 0; }
  footer { margin-top:40px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:12px; }
  @media print { body { background:#fff; } .wrap { box-shadow:none; max-width:none; } }
</style></head><body><div class="wrap">"""
