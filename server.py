"""MalLab web server: serves the lab UI and its JSON API on this computer only.

    python server.py                 # http://127.0.0.1:7860, opens your browser
    python server.py --no-browser --port 7861 --lab-root D:\\scratch\\lab

Every request must come from this machine (loopback peer, loopback Host header, and no
cross-site Origin / Sec-Fetch-Site), so other devices and web pages can't drive the lab.
"""

import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import webbrowser
from pathlib import Path
from urllib.parse import unquote

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from starlette.routing import Route

from mallab import MalLab, fakenet

FROZEN = getattr(sys, "frozen", False)   # running from the packaged MalLab.exe
HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
UI_FILE = HERE / "ui" / "lab.html"
FONTS_DIR = HERE / "ui" / "fonts"   # bundled SIL OFL fonts (no external requests from the UI)


def default_lab_root() -> Path:
    """MALLAB_ROOT if set; %LOCALAPPDATA%\\MalLab\\lab for the installed app (Program Files is
    read-only); otherwise .\\lab next to this file."""
    if os.environ.get("MALLAB_ROOT"):
        return Path(os.environ["MALLAB_ROOT"])
    if FROZEN:
        return Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "MalLab" / "lab"
    return HERE / "lab"
MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # raw upload cap (archives included); members are capped separately


class Hub:
    """Fan lab events out to every open browser tab (Server-Sent Events)."""

    def __init__(self):
        self.loop: asyncio.AbstractEventLoop | None = None
        self.queues: set[asyncio.Queue] = set()

    def publish(self, event: dict):
        if self.loop:
            for q in list(self.queues):
                self.loop.call_soon_threadsafe(q.put_nowait, event)


def _loopback(host: str) -> bool:
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_only(value: str) -> str:
    """'127.0.0.1:7860' -> '127.0.0.1', '[::1]:7860' -> '::1'."""
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


class LocalOnly:
    """Refuse requests from other machines, DNS-rebinding hosts, and cross-site web pages."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
            peer = (scope.get("client") or ("", 0))[0]
            host = _host_only(headers.get("host", ""))
            origin = headers.get("origin")
            origin_host = _host_only(origin.split("//", 1)[-1]) if origin else ""
            cross_site = headers.get("sec-fetch-site") == "cross-site"
            if not _loopback(peer) or not _loopback(host) or (origin and not _loopback(origin_host)) or cross_site:
                return await PlainTextResponse("Forbidden", status_code=403)(scope, receive, send)
        await self.app(scope, receive, send)


def _err(e: Exception, status: int = 400) -> JSONResponse:
    msg = str(e) if isinstance(e, (ValueError, RuntimeError)) else f"{type(e).__name__}: {e}"
    return JSONResponse({"error": msg}, status_code=status)


async def _body(request: Request) -> dict:
    """The JSON body as a dict; malformed JSON, a list or a bare value becomes {} (a 400-style
    'missing field' path in each route) instead of a 500."""
    try:
        b = await request.json()
    except ValueError:
        return {}
    return b if isinstance(b, dict) else {}


def _int(v, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(int(v), hi))
    except (TypeError, ValueError):
        return default


def _unpack_opts(headers) -> tuple[bool, str | None]:
    """Archive handling for raw uploads: X-Unpack: 0 keeps an archive whole;
    X-Archive-Password (URL-encoded) overrides the default "infected" convention."""
    pw = unquote(headers.get("x-archive-password") or "").strip()
    return headers.get("x-unpack", "1") != "0", pw or None


async def _read_upload(request: Request) -> tuple[bytes | None, JSONResponse | None]:
    """Read a raw upload body, refusing anything over MAX_UPLOAD_BYTES without buffering it all."""
    if int(request.headers.get("content-length") or 0) > MAX_UPLOAD_BYTES:
        return None, JSONResponse({"error": f"upload exceeds {MAX_UPLOAD_BYTES // 2**20} MB"}, status_code=413)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            return None, JSONResponse({"error": f"upload exceeds {MAX_UPLOAD_BYTES // 2**20} MB"}, status_code=413)
        chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        return None, JSONResponse({"error": "empty upload"}, status_code=400)
    return data, None


def build_app(lab: MalLab, hub: Hub, ui_file: Path = UI_FILE) -> Starlette:
    def background(fn, on_error_type: str = "lab_log", **extra):
        def run():
            try:
                fn()
            except Exception as e:
                hub.publish({"session": "lab", "type": on_error_type, **extra,
                             "text": str(e), "error": f"{type(e).__name__}: {e}"})
        threading.Thread(target=run, daemon=True).start()

    async def page(request):
        return FileResponse(ui_file, headers={"Cache-Control": "no-cache"})

    async def font(request):
        name = request.path_params["name"]
        p = FONTS_DIR / name
        if not re.fullmatch(r"[a-z0-9-]+\.woff2", name) or not p.is_file():
            return PlainTextResponse("Not found", status_code=404)
        return FileResponse(p, media_type="font/woff2", headers={"Cache-Control": "max-age=604800"})

    async def events(request: Request):
        queue: asyncio.Queue = asyncio.Queue()
        hub.queues.add(queue)

        async def stream():
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15)
                        yield f"data: {json.dumps(event, default=str)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
                    if await request.is_disconnected():
                        break
            finally:
                hub.queues.discard(queue)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    async def state(request):
        return JSONResponse(await asyncio.to_thread(lab.state))

    # ---- cases
    async def case_create(request):
        b = await _body(request)
        return JSONResponse(lab.store.create_case(str(b.get("name", "")), str(b.get("description", ""))))

    async def case_get(request):
        d = await asyncio.to_thread(lab.case_detail, request.path_params["cid"])
        return JSONResponse(d) if d else JSONResponse({"error": "no such case"}, status_code=404)

    async def case_update(request):
        b = await _body(request)
        fields = {k: str(b[k]) for k in ("name", "description", "notes", "tags") if b.get(k) is not None}
        c = lab.store.update_case(request.path_params["cid"], **fields)
        return JSONResponse(c) if c else JSONResponse({"error": "no such case"}, status_code=404)

    async def case_delete(request):
        await asyncio.to_thread(lab.delete_case, request.path_params["cid"])
        return JSONResponse({"ok": True})

    async def case_iocs(request):
        return JSONResponse(await asyncio.to_thread(lab.case_iocs, request.path_params["cid"]))

    async def case_compare(request):
        return JSONResponse(await asyncio.to_thread(lab.compare_case, request.path_params["cid"]))

    async def case_report(request):
        cid = request.path_params["cid"]
        try:
            md = await asyncio.to_thread(lab.export_report, cid)
        except ValueError as e:
            return _err(e, 404)
        case = lab.store.get_case(cid)
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", case["name"] if case else cid).strip("_") or "case"
        return PlainTextResponse(md, media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{name}-report.md"'})

    async def case_ioc_export(request):
        cid = request.path_params["cid"]
        try:
            body, media, ext = await asyncio.to_thread(lab.export_iocs, cid, request.query_params.get("format", "csv"))
        except ValueError as e:
            return _err(e, 404 if "no such case" in str(e) else 400)
        case = lab.store.get_case(cid)
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", case["name"]).strip("_") or "case"
        return PlainTextResponse(body, media_type=media,
                                 headers={"Content-Disposition": f'attachment; filename="{name}-iocs.{ext}"'})

    # ---- adding samples
    async def upload(request):
        data, bad = await _read_upload(request)
        if bad:
            return bad
        try:
            return JSONResponse(await asyncio.to_thread(
                lab.ingest_any, request.path_params["cid"], data,
                request.headers.get("x-filename", "sample.bin"), "upload", *_unpack_opts(request.headers)))
        except Exception as e:
            return _err(e)

    async def acquire(request):
        b = await _body(request)
        cid = request.path_params["cid"]
        opts = (b.get("unpack", True) is not False, (b.get("password") or "").strip() or None)
        try:
            if b.get("hash"):
                return JSONResponse(await asyncio.to_thread(lab.acquire_hash, cid, b["hash"].strip(), *opts))
            if b.get("url"):
                return JSONResponse(await asyncio.to_thread(lab.acquire_url, cid, b["url"].strip(), *opts))
            return JSONResponse({"error": "provide a hash or url"}, status_code=400)
        except Exception as e:
            return _err(e)

    async def search(request):
        b = await _body(request)
        try:
            return JSONResponse({"results": await asyncio.to_thread(
                lab.search_repo, str(b.get("query", "")), _int(b.get("limit"), 25, 1, 100))})
        except Exception as e:
            return _err(e)

    async def quick(request):
        data, bad = await _read_upload(request)
        if bad:
            return bad
        qp = request.query_params
        unpack, password = _unpack_opts(request.headers)
        name = request.headers.get("x-filename", "sample.bin")
        opts = {"timeout": _int(qp.get("timeout"), 60, 5, 300), "networking": qp.get("networking") == "1",
                "do_detonate": qp.get("detonate", "1") != "0", "safe_net": qp.get("safe_net", "1") != "0",
                "simulate": qp.get("simulate") == "1", "unpack": unpack, "password": password}
        if opts["do_detonate"] and opts["simulate"] and not lab.fakenet_status()["ready"]:
            return _err(RuntimeError(fakenet.missing_message(lab.tools_dir)))

        def run():
            result = lab.quick_detonate(data, name, **opts)
            hub.publish({"session": "lab", "type": "lab_quick_done", "result": result})
        background(run, on_error_type="lab_quick_done")
        return JSONResponse({"ok": True})

    # ---- samples
    async def static_report(request):
        r = await asyncio.to_thread(lab.static_report, request.path_params["sid"])
        return JSONResponse(r) if r else JSONResponse({"error": "no static report"}, status_code=404)

    async def detections(request):
        return JSONResponse(await asyncio.to_thread(lab.detections, request.path_params["sid"]))

    async def verdict(request):
        return await _call(lab.sample_verdict, request.path_params["sid"])

    async def annotate(request):
        b = await _body(request)
        try:
            return JSONResponse(await asyncio.to_thread(lab.annotate_sample, request.path_params["sid"],
                                                        b.get("notes"), b.get("labels")))
        except ValueError as e:
            return _err(e, 404)

    async def related(request):
        try:
            return JSONResponse({"related": await asyncio.to_thread(lab.related_samples, request.path_params["sid"])})
        except ValueError as e:
            return _err(e, 404)

    def _call(fn, *a, status=400):
        """Run a lab call off the event loop; ValueError/RuntimeError -> JSON error."""
        async def go():
            try:
                return JSONResponse(await asyncio.to_thread(fn, *a))
            except (ValueError, RuntimeError) as e:
                return _err(e, 404 if "no such" in str(e) else status)
        return go()

    async def yara_generate(request):
        return await _call(lab.generate_yara, request.path_params["sid"])

    async def case_attck(request):
        return await _call(lambda c: {"matrix": lab.case_attck(c)}, request.path_params["cid"])

    async def case_timeline(request):
        return await _call(lambda c: {"events": lab.case_timeline(c)}, request.path_params["cid"])

    async def case_enrich(request):
        b = await _body(request)
        return await _call(lab.enrich_case_iocs, request.path_params["cid"], bool(b.get("refresh")))

    async def case_groups(request):
        return JSONResponse({"links": await asyncio.to_thread(
            lab.store.actor_links, None, "case", request.path_params["cid"])})

    async def actors_list(request):
        return await _call(lambda: {"actors": lab.actors()})

    async def actor_get(request):
        return await _call(lab.actor_profile, request.path_params["aid"])

    async def actor_save(request):
        b = await _body(request)
        return await _call(lab.save_actor, b.get("id") or None, b)

    async def actor_delete(request):
        await asyncio.to_thread(lab.delete_actor, request.path_params["aid"])
        return JSONResponse({"ok": True})

    async def actor_link(request):
        b = await _body(request)
        return await _call(lab.link_actor, request.path_params["aid"], str(b.get("kind", "")),
                           str(b.get("target_id", "")), str(b.get("confidence", "low")),
                           str(b.get("note", "")), bool(b.get("unlink")))

    async def actor_suggest(request):
        return await _call(lab.suggest_actors, request.path_params["sid"])

    async def actors_import(request):
        def run():
            res = lab.import_actor_catalog()
            hub.publish({"session": "lab", "type": "lab_actors_imported", **res})
        background(run, on_error_type="lab_actors_imported")
        return JSONResponse({"ok": True})

    async def blu_arm(request):
        b = await _body(request)
        return await _call(lab.set_blu_mode, bool(b.get("arm")), str(b.get("confirm", "")))

    async def host_observe(request):
        b = await _body(request)
        sid = request.path_params["sid"]
        if lab.detonating:
            return JSONResponse({"error": "a run is already in progress"}, status_code=409)
        seconds = _int(b.get("seconds"), 60, 10, 1800)
        confirm = str(b.get("confirm", ""))
        # Validate the gate synchronously so the UI gets a clear error; then run in the background.
        st = lab.blu_status()
        if not st["armed"]:
            return _err(RuntimeError("BLU MODE is not armed. Arm it in Settings first."))
        if confirm.strip().upper() != st["token"]:
            return _err(ValueError("confirmation phrase does not match"), 400)
        background(lambda: lab.host_observe(sid, seconds=seconds, confirm=confirm))
        return JSONResponse({"ok": True})

    async def sandbox_open(request):
        b = await _body(request)
        try:
            return JSONResponse(await asyncio.to_thread(lab.open_sandbox, b.get("sample_id") or None))
        except Exception as e:
            return _err(e)

    async def intel(request):
        b = await _body(request)
        try:
            return JSONResponse(await asyncio.to_thread(lab.threat_intel, request.path_params["sid"],
                                                        bool(b.get("refresh"))))
        except Exception as e:
            return _err(e)

    async def detonate(request):
        b = await _body(request)
        sid = request.path_params["sid"]
        if lab.detonating:
            return JSONResponse({"error": "a detonation is already running"}, status_code=409)
        opts = {"timeout": _int(b.get("timeout"), 60, 5, 300), "networking": bool(b.get("networking")),
                "do_detonate": bool(b.get("do_detonate", True)), "safe_net": bool(b.get("safe_net", True)),
                "simulate": bool(b.get("simulate"))}
        if opts["simulate"] and not lab.fakenet_status()["ready"]:
            return _err(RuntimeError(fakenet.missing_message(lab.tools_dir)))
        background(lambda: lab.detonate(sid, **opts))
        return JSONResponse({"ok": True})

    async def dynamic(request):
        r = await asyncio.to_thread(lab.dynamic_report, request.path_params["sid"], request.path_params["rid"])
        return JSONResponse(r) if r else JSONResponse({"error": "no report"}, status_code=404)

    async def screenshot(request):
        p = lab.screenshot_path(request.path_params["sid"], request.path_params["rid"])
        return FileResponse(p, media_type="image/png") if p else JSONResponse({"error": "no screenshot"}, status_code=404)

    async def pcap(request):
        p = lab.pcap_path(request.path_params["sid"], request.path_params["rid"])
        if not p:
            return JSONResponse({"error": "no capture"}, status_code=404)
        return FileResponse(p, media_type="application/vnd.tcpdump.pcap", filename=p.name)

    async def diff(request):
        b = await _body(request)
        try:
            return JSONResponse(await asyncio.to_thread(lab.diff_runs, request.path_params["sid"],
                                                        b.get("run_a"), b.get("run_b")))
        except Exception as e:
            return _err(e)

    # ---- YARA
    async def yara_list(request):
        return JSONResponse({"rules": await asyncio.to_thread(lab.yara_list)})

    async def yara_get(request):
        try:
            return JSONResponse({"name": request.path_params["name"], "text": lab.yara_read(request.path_params["name"])})
        except ValueError as e:
            return _err(e, 404)

    async def yara_save(request):
        b = await _body(request)
        try:
            return JSONResponse(lab.yara_write(str(b.get("name", "")), str(b.get("text", ""))))
        except ValueError as e:
            return _err(e)

    async def yara_retrohunt(request):
        b = await _body(request)
        return await _call(lab.retrohunt, b.get("name") or None, b.get("text") or None)

    async def yara_packs(request):
        return JSONResponse({"packs": await asyncio.to_thread(lab.yara_packs)})

    async def yara_delete(request):
        try:
            lab.yara_delete(request.path_params["name"])
        except ValueError as e:
            return _err(e)
        return JSONResponse({"ok": True})

    # ---- settings
    async def config(request):
        b = await _body(request)
        lab.set_keys(**{k: b.get(k) for k in ("vx_key", "vx_url", "vt_key", "abusech_key", "ha_key", "otx_key")})
        return JSONResponse({"ok": True, **await asyncio.to_thread(lab.state)})

    async def defender_route(request):
        if request.method == "GET":
            return JSONResponse(await asyncio.to_thread(lab.defender_status))
        b = await _body(request)
        try:
            return JSONResponse(await asyncio.to_thread(lab.set_defender_exclusion, bool(b.get("exclude"))))
        except Exception as e:
            return _err(e)

    async def netguard_route(request):
        if request.method == "GET":
            return JSONResponse(await asyncio.to_thread(lab.netguard_status))
        b = await _body(request)
        try:
            return JSONResponse(await asyncio.to_thread(lab.set_netguard, bool(b.get("enable"))))
        except Exception as e:
            return _err(e)

    async def sysmon_setup(request):
        def run():
            lab.setup_sysmon()
            hub.publish({"session": "lab", "type": "lab_sysmon", **lab.sysmon_status()})
        background(run)
        return JSONResponse({"ok": True})

    async def setup_clear(request):
        await asyncio.to_thread(lab.clear_setup_pending)
        return JSONResponse({"ok": True})

    async def tool_setup(request):
        tool = request.path_params["tool"]
        if tool not in ("capa", "fakenet", "sysmon", "hollows_hunter", "sigma", "yara_forge"):
            return JSONResponse({"error": "unknown tool"}, status_code=404)

        def run():
            lab.setup_tool(tool)
            hub.publish({"session": "lab", "type": "lab_tool_ready", "tool": tool})
        background(run, on_error_type="lab_tool_ready", tool=tool)
        return JSONResponse({"ok": True})

    @contextlib.asynccontextmanager
    async def lifespan(app):
        hub.loop = asyncio.get_running_loop()
        yield

    return Starlette(lifespan=lifespan, routes=[
        Route("/", page),
        Route("/lab", lambda r: RedirectResponse("/")),
        Route("/fonts/{name}", font),
        Route("/api/events", events),
        Route("/api/lab/state", state),
        Route("/api/lab/case", case_create, methods=["POST"]),
        Route("/api/lab/case/{cid}", case_get),
        Route("/api/lab/case/{cid}/update", case_update, methods=["POST"]),
        Route("/api/lab/case/{cid}/delete", case_delete, methods=["POST"]),
        Route("/api/lab/case/{cid}/upload", upload, methods=["POST"]),
        Route("/api/lab/case/{cid}/acquire", acquire, methods=["POST"]),
        Route("/api/lab/case/{cid}/iocs", case_iocs),
        Route("/api/lab/case/{cid}/compare", case_compare),
        Route("/api/lab/case/{cid}/report", case_report),
        Route("/api/lab/case/{cid}/iocs/export", case_ioc_export),
        Route("/api/lab/sample/{sid}/annotate", annotate, methods=["POST"]),
        Route("/api/lab/sample/{sid}/related", related),
        Route("/api/lab/sandbox/open", sandbox_open, methods=["POST"]),
        Route("/api/lab/blu/arm", blu_arm, methods=["POST"]),
        Route("/api/lab/sample/{sid}/observe", host_observe, methods=["POST"]),
        Route("/api/lab/sample/{sid}/yara", yara_generate),
        Route("/api/lab/sample/{sid}/actors", actor_suggest),
        Route("/api/lab/case/{cid}/attck", case_attck),
        Route("/api/lab/case/{cid}/timeline", case_timeline),
        Route("/api/lab/case/{cid}/enrich", case_enrich, methods=["POST"]),
        Route("/api/lab/case/{cid}/groups", case_groups),
        Route("/api/lab/actors", actors_list),
        Route("/api/lab/actors/save", actor_save, methods=["POST"]),
        Route("/api/lab/actors/import", actors_import, methods=["POST"]),
        Route("/api/lab/actors/{aid}", actor_get),
        Route("/api/lab/actors/{aid}/delete", actor_delete, methods=["POST"]),
        Route("/api/lab/actors/{aid}/link", actor_link, methods=["POST"]),
        Route("/api/lab/search", search, methods=["POST"]),
        Route("/api/lab/quick", quick, methods=["POST"]),
        Route("/api/lab/sample/{sid}/static", static_report),
        Route("/api/lab/sample/{sid}/detections", detections),
        Route("/api/lab/sample/{sid}/verdict", verdict),
        Route("/api/lab/sample/{sid}/intel", intel, methods=["POST"]),
        Route("/api/lab/sample/{sid}/detonate", detonate, methods=["POST"]),
        Route("/api/lab/sample/{sid}/dynamic/{rid}", dynamic),
        Route("/api/lab/sample/{sid}/screenshot/{rid}", screenshot),
        Route("/api/lab/sample/{sid}/pcap/{rid}", pcap),
        Route("/api/lab/sample/{sid}/diff", diff, methods=["POST"]),
        Route("/api/lab/yara", yara_list),
        Route("/api/lab/yara/save", yara_save, methods=["POST"]),
        Route("/api/lab/yara/retrohunt", yara_retrohunt, methods=["POST"]),
        Route("/api/lab/yara/packs", yara_packs),
        Route("/api/lab/yara/{name}", yara_get),
        Route("/api/lab/yara/{name}/delete", yara_delete, methods=["POST"]),
        Route("/api/lab/config", config, methods=["POST"]),
        Route("/api/lab/defender", defender_route, methods=["GET", "POST"]),
        Route("/api/lab/netguard", netguard_route, methods=["GET", "POST"]),
        Route("/api/lab/sysmon/setup", sysmon_setup, methods=["POST"]),
        Route("/api/lab/tools/{tool}/setup", tool_setup, methods=["POST"]),
        Route("/api/lab/setup-pending/clear", setup_clear, methods=["POST"]),
    ])


def _port_in_use(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main():
    p = argparse.ArgumentParser(description="MalLab: a local malware research lab.")
    p.add_argument("--lab-root", default=str(default_lab_root()),
                   help="where cases, quarantine, reports, YARA rules and tools live (env: MALLAB_ROOT)")
    p.add_argument("--port", type=int, default=7860)
    p.add_argument("--no-browser", action="store_true")
    args = p.parse_args()

    url = f"http://127.0.0.1:{args.port}/"
    if _port_in_use(args.port):
        print(f"Port {args.port} is already in use; MalLab is probably already running at {url}")
        if not args.no_browser:
            webbrowser.open(url)
        return

    hub = Hub()
    lab = MalLab(Path(args.lab_root), emit=hub.publish)
    print(f"MalLab: {url}  (lab data: {Path(args.lab_root).resolve()})")
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    uvicorn.run(LocalOnly(build_app(lab, hub)), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
