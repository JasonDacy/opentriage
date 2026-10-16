"""In-memory mock of the Confluence Cloud endpoints OpenTriage uses. Requires a session cookie,
which the /wiki/ HTML page sets, so tests prove requests run with the signed-in tab's session."""
import json
import re
from urllib.parse import unquote, urlparse

STATE = {}


def reset():
    STATE.clear()
    STATE.update(
        next=300,
        pages={
            "100": {"id": "100", "title": "Incident Response Playbooks", "version": 1, "storage": "<p>folder</p>"},
            "101": {"id": "101", "title": "Zeta Detection", "version": 1, "storage": "<p>z</p>"},
            "102": {"id": "102", "title": "[Heuristic Attribute] Alpha Detection", "version": 1, "storage": "<p>a</p>"},
            "200": {"id": "200", "title": "IR Playbook Index", "version": 3,
                    "storage": "<table><tbody><tr><th><p>Model name</p></th><th><p>Tactic</p></th></tr></tbody></table>"},
        },
        order=["101", "102"],
        unauthenticated=0,
    )


reset()

PAGE_HTML = b"""<!doctype html><html><head><meta charset="utf-8"><title>IR Playbook Index - Example Wiki</title></head>
<body><h1>IR Playbook Index</h1><p>Mock Confluence space IR.</p></body></html>"""


def handle(h, method):
    """Return True if handled. `h` is a BaseHTTPRequestHandler."""
    path = h.path
    if not path.startswith("/wiki"):
        return False
    if not path.startswith("/wiki/api/") and not path.startswith("/wiki/rest/"):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.send_header("Set-Cookie", "confsession=ok; Path=/; Secure; SameSite=Lax")
        h.end_headers()
        h.wfile.write(PAGE_HTML)
        return True
    if "confsession=ok" not in (h.headers.get("Cookie") or ""):
        STATE["unauthenticated"] += 1
        return reply(h, 401, {"message": "not signed in"})
    body = None
    if method in ("POST", "PUT"):
        n = int(h.headers.get("Content-Length") or 0)
        body = json.loads(h.rfile.read(n) or b"null") if n else None
    pages, order = STATE["pages"], STATE["order"]
    m = re.match(r"^/wiki/api/v2/pages/(\d+)\?body-format=storage$", path)
    if m and method == "GET":
        p = pages.get(m.group(1))
        if not p:
            return reply(h, 404, {})
        return reply(h, 200, {"id": p["id"], "title": p["title"], "spaceId": "9", "parentId": "100", "parentType": "page",
                              "version": {"number": p["version"]}, "body": {"storage": {"value": p["storage"]}}, "_links": {"webui": f"/spaces/IR/pages/{p['id']}"}})
    if path.startswith("/wiki/api/v2/spaces?keys=IR"):
        return reply(h, 200, {"results": [{"id": "9"}]})
    if path.startswith("/wiki/rest/api/content/search"):
        cql = unquote(urlparse(path).query)
        t = re.search(r'title ~ "([^"]*)"', cql)
        hits = [p for p in pages.values() if t and t.group(1).lower() in p["title"].lower()]
        return reply(h, 200, {"results": [{"id": p["id"], "title": p["title"], "_links": {"webui": f"/x/{p['id']}"}} for p in hits]})
    if path == "/wiki/api/v2/pages" and method == "POST":
        pid = str(STATE["next"]); STATE["next"] += 1
        pages[pid] = {"id": pid, "title": body["title"], "version": 1, "storage": body["body"]["value"]}
        if body.get("parentId") == "100":
            order.append(pid)
        return reply(h, 200, {"id": pid, "title": body["title"], "version": {"number": 1}, "_links": {"webui": f"/spaces/IR/pages/{pid}"}})
    m = re.match(r"^/wiki/api/v2/pages/(\d+)$", path)
    if m and method == "PUT":
        p = pages[m.group(1)]
        if body["version"]["number"] != p["version"] + 1:
            return reply(h, 409, {"message": "version conflict"})
        p.update(title=body["title"], storage=body["body"]["value"], version=body["version"]["number"])
        return reply(h, 200, {"id": p["id"], "title": p["title"], "version": {"number": p["version"]}})
    if path.startswith("/wiki/api/v2/pages/100/direct-children"):
        return reply(h, 200, {"results": [{"id": i, "title": pages[i]["title"], "type": "page"} for i in order]})
    m = re.match(r"^/wiki/rest/api/content/(\d+)/move/(before|after)/(\d+)$", path)
    if m and method == "PUT":
        order.remove(m.group(1))
        t = order.index(m.group(3))
        order.insert(t if m.group(2) == "before" else t + 1, m.group(1))
        return reply(h, 200, {})
    return reply(h, 500, {"message": f"unmocked {method} {path}"})


def reply(h, status, obj):
    data = json.dumps(obj).encode()
    h.send_response(status)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(data)))
    h.end_headers()
    h.wfile.write(data)
    return True
