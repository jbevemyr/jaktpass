#!/usr/bin/env python3
"""
Minimal Python-server för lokal testning (deps-fri, endast stdlib).

- Serverar SPA från priv/www (history fallback till index.html)
- Implementerar samma JSON-API som Yaws-appmod under /api
- Persistens: samma filstruktur under JAKTPASS_DATA_DIR (default ./data)
- Admin: Basic Auth för /api/admin/*

Kör:
  python3 pyserver/jaktpass_pyserver.py --port 8000
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import email
import hashlib
import io
import json
import mimetypes
import os
import re
import shutil
import threading
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

V2_LOCK = threading.Lock()


def now_rfc3339() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def getenv_default(key: str, default: str) -> str:
    return os.environ.get(key) or default


def data_dir() -> Path:
    return Path(getenv_default("JAKTPASS_DATA_DIR", "./priv/data")).resolve()


def sets_dir() -> Path:
    return data_dir() / "sets"


def set_dir(set_id: str) -> Path:
    return sets_dir() / set_id


def meta_path(set_id: str) -> Path:
    return set_dir(set_id) / "meta.json"

def leaderboard_path(set_id: str) -> Path:
    return set_dir(set_id) / "leaderboard.json"


def atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    b = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    tmp.write_bytes(b)
    tmp.replace(path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_bytes().decode("utf-8"))


def content_type_from_filename(name: str) -> str:
    ct, _ = mimetypes.guess_type(name)
    return ct or "application/octet-stream"


def uuid_v4() -> str:
    return str(uuid.uuid4())


def clamp01(x: Any) -> Optional[float]:
    try:
        v = float(x)
    except Exception:
        return None
    if v < 0.0 or v > 1.0:
        return None
    return float(v)


def validate_nonempty_string(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s if s else None
    return None


def validate_polygon(poly: Any) -> Optional[List[Dict[str, float]]]:
    if not isinstance(poly, list) or len(poly) < 3:
        return None
    out: List[Dict[str, float]] = []
    for p in poly:
        if not isinstance(p, dict):
            return None
        x = clamp01(p.get("x"))
        y = clamp01(p.get("y"))
        if x is None or y is None:
            return None
        out.append({"x": x, "y": y})
    return out


def point_in_polygon(px: float, py: float, poly: List[Tuple[float, float]]) -> bool:
    # Ray casting
    inside = False
    n = len(poly)
    for i in range(n):
        x1, y1 = poly[i]
        x2, y2 = poly[(i + 1) % n]
        if ((y1 > py) != (y2 > py)):
            xinters = (x2 - x1) * (py - y1) / ((y2 - y1) or 1e-12) + x1
            if px < xinters:
                inside = not inside
    return inside


def filter_stands_in_polygon(stands: List[Dict[str, Any]], polygon: List[Dict[str, float]]) -> List[Dict[str, Any]]:
    poly = [(p["x"], p["y"]) for p in polygon]
    out = []
    for s in stands:
        x = float(s.get("x", 0.0))
        y = float(s.get("y", 0.0))
        if point_in_polygon(x, y, poly):
            out.append(s)
    return out


def shuffle_take(items: List[Any], count: int) -> List[Any]:
    import random
    items2 = list(items)
    random.shuffle(items2)
    return items2[: max(0, min(count, len(items2)))]


def png_dims(b: bytes) -> Tuple[Optional[int], Optional[int]]:
    if len(b) < 24:
        return None, None
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return None, None
    # IHDR chunk: length (4) + type (4) + width (4) + height (4)
    if b[12:16] != b"IHDR":
        return None, None
    w = int.from_bytes(b[16:20], "big")
    h = int.from_bytes(b[20:24], "big")
    return w, h


def jpeg_dims(b: bytes) -> Tuple[Optional[int], Optional[int]]:
    if len(b) < 4 or b[:2] != b"\xff\xd8":
        return None, None
    i = 2
    while i + 4 <= len(b):
        if b[i] != 0xFF:
            i += 1
            continue
        marker = b[i + 1]
        i += 2
        if marker == 0xD9:  # EOI
            return None, None
        if i + 2 > len(b):
            return None, None
        seglen = int.from_bytes(b[i : i + 2], "big")
        if seglen < 2:
            return None, None
        if marker in (0xC0, 0xC2) and i + 7 <= len(b):
            # [len][precision][height][width]
            h = int.from_bytes(b[i + 3 : i + 5], "big")
            w = int.from_bytes(b[i + 5 : i + 7], "big")
            return w, h
        i += seglen
    return None, None


def webp_dims(b: bytes) -> Tuple[Optional[int], Optional[int]]:
    if len(b) < 16 or b[:4] != b"RIFF" or b[8:12] != b"WEBP":
        return None, None
    i = 12
    while i + 8 <= len(b):
        fourcc = b[i : i + 4]
        size = int.from_bytes(b[i + 4 : i + 8], "little")
        i += 8
        chunk = b[i : i + size]
        if fourcc == b"VP8X" and len(chunk) >= 10:
            # flags(1) + reserved(3) + width-1(3) + height-1(3)
            w = int.from_bytes(chunk[4:7], "little") + 1
            h = int.from_bytes(chunk[7:10], "little") + 1
            return w, h
        pad = size % 2
        i += size + pad
    return None, None


def image_dims(ext: str, b: bytes) -> Tuple[Optional[int], Optional[int]]:
    ext = ext.lower()
    if ext == "png":
        return png_dims(b)
    if ext in ("jpg", "jpeg"):
        return jpeg_dims(b)
    if ext == "webp":
        return webp_dims(b)
    return None, None


def image_ext(filename: str) -> Optional[str]:
    ext = Path(filename).suffix.lower()
    if ext == ".png":
        return "png"
    if ext == ".jpg":
        return "jpg"
    if ext == ".jpeg":
        return "jpeg"
    if ext == ".webp":
        return "webp"
    return None


def validate_symbol(sym: Any) -> str:
    s = str(sym or "").strip().lower()
    if not s or s == "dot" or s == "circle":
        return "dot"
    if s in ("square", "triangle", "cross", "star"):
        return s
    return "dot"


_SETID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def validate_set_id(set_id: str) -> bool:
    return bool(_SETID_RE.match(set_id or ""))


# -------------------------
# V2 (multi-admin) paths
# -------------------------


def v2_dir() -> Path:
    return data_dir() / "v2"


def v2_admins_dir() -> Path:
    return v2_dir() / "admins"


def v2_admin_dir(admin_id: str) -> Path:
    return v2_admins_dir() / admin_id


def v2_admin_path(admin_id: str) -> Path:
    return v2_admin_dir(admin_id) / "admin.json"


def v2_admin_sets_dir(admin_id: str) -> Path:
    return v2_admin_dir(admin_id) / "sets"


def v2_set_dir(admin_id: str, set_id: str) -> Path:
    return v2_admin_sets_dir(admin_id) / set_id


def v2_set_meta_path(admin_id: str, set_id: str) -> Path:
    return v2_set_dir(admin_id, set_id) / "meta.json"

def v2_leaderboard_path(admin_id: str, set_id: str) -> Path:
    return v2_set_dir(admin_id, set_id) / "leaderboard.json"


def v2_sessions_dir() -> Path:
    return v2_dir() / "sessions"


def v2_session_path(token: str) -> Path:
    return v2_sessions_dir() / f"{token}.json"


def v2_shares_dir() -> Path:
    return v2_dir() / "shares"


def v2_share_path(share_id: str) -> Path:
    return v2_shares_dir() / f"{share_id}.json"


def v2_index_path() -> Path:
    return v2_dir() / "admin_index.json"


def v2_cookie_name() -> str:
    return "jaktpass_v2"


def base64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def normalize_mode(mode: str) -> str:
    m = (mode or "").strip()
    if m in ("rand10", "randHalf", "all"):
        return m
    if m == "half":
        return "randHalf"
    if m == "rand":
        return "rand10"
    return "all"


def validate_email(email: Any) -> Optional[str]:
    s = str(email or "").strip()
    if not s or "@" not in s or "." not in s:
        return None
    if " " in s:
        return None
    return s.lower()


def validate_password(pw: Any) -> Optional[str]:
    s = str(pw or "")
    if len(s) < 8:
        return None
    return s


def pbkdf2_sha256(password: str, salt: bytes, iterations: int = 100_000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dklen)


def v2_index_load() -> Dict[str, str]:
    try:
        d = read_json(v2_index_path())
        return d if isinstance(d, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def v2_index_save(d: Dict[str, str]) -> None:
    atomic_write_json(v2_index_path(), d)


def v2_load_admin(admin_id: str) -> Dict[str, Any]:
    return read_json(v2_admin_path(admin_id))


def v2_save_admin(admin_id: str, admin: Dict[str, Any]) -> None:
    atomic_write_json(v2_admin_path(admin_id), admin)


def v2_new_session(admin_id: str) -> str:
    tok = base64url(os.urandom(24))
    atomic_write_json(v2_session_path(tok), {"adminId": admin_id, "createdAt": now_rfc3339()})
    return tok


def v2_load_session(token: str) -> Optional[Dict[str, Any]]:
    try:
        d = read_json(v2_session_path(token))
        return d if isinstance(d, dict) else None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def v2_delete_session(token: str) -> None:
    try:
        v2_session_path(token).unlink()
    except FileNotFoundError:
        pass
    except Exception:
        pass


def v2_new_share(admin_id: str, set_id: str) -> str:
    sid = base64url(os.urandom(18))
    atomic_write_json(v2_share_path(sid), {"adminId": admin_id, "setId": set_id, "createdAt": now_rfc3339()})
    return sid


def v2_load_share(share_id: str) -> Optional[Dict[str, Any]]:
    try:
        d = read_json(v2_share_path(share_id))
        return d if isinstance(d, dict) else None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def v2_load_set_meta(admin_id: str, set_id: str) -> Dict[str, Any]:
    return read_json(v2_set_meta_path(admin_id, set_id))


def v2_save_set_meta(admin_id: str, set_id: str, meta: Dict[str, Any]) -> None:
    atomic_write_json(v2_set_meta_path(admin_id, set_id), meta)


def v2_load_leaderboard(admin_id: str, set_id: str) -> List[Dict[str, Any]]:
    p = v2_leaderboard_path(admin_id, set_id)
    try:
        data = read_json(p)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except Exception:
        return []


def v2_save_leaderboard(admin_id: str, set_id: str, items: List[Dict[str, Any]]) -> None:
    atomic_write_json(v2_leaderboard_path(admin_id, set_id), items)


_SET_LOCKS: Dict[str, threading.Lock] = {}
_SET_LOCKS_GUARD = threading.Lock()


def with_set_lock(set_id: str):
    class _Ctx:
        def __enter__(self):
            with _SET_LOCKS_GUARD:
                _SET_LOCKS.setdefault(set_id, threading.Lock())
                self._lock = _SET_LOCKS[set_id]
            self._lock.acquire()

        def __exit__(self, exc_type, exc, tb):
            self._lock.release()
            return False

    return _Ctx()


def list_sets() -> List[Dict[str, Any]]:
    root = sets_dir()
    if not root.exists():
        return []
    out = []
    for p in sorted(root.iterdir()):
        if not p.is_dir():
            continue
        mp = p / "meta.json"
        if not mp.exists():
            continue
        try:
            meta = read_json(mp)
            name = (((meta or {}).get("set") or {}).get("name")) or ""
            has_image = bool(((meta or {}).get("image") or {}).get("filename"))
            out.append({"id": p.name, "name": name, "hasImage": has_image})
        except Exception:
            continue
    return out


def load_set_meta(set_id: str) -> Dict[str, Any]:
    return read_json(meta_path(set_id))


def save_set_meta(set_id: str, meta: Dict[str, Any]) -> None:
    atomic_write_json(meta_path(set_id), meta)


def load_leaderboard(set_id: str) -> List[Dict[str, Any]]:
    p = leaderboard_path(set_id)
    try:
        data = read_json(p)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except Exception:
        return []


def save_leaderboard(set_id: str, items: List[Dict[str, Any]]) -> None:
    atomic_write_json(leaderboard_path(set_id), items)


def normalize_mode(mode: str) -> str:
    m = (mode or "").strip()
    if m in ("rand10", "randHalf", "all"):
        return m
    if m == "half":
        return "randHalf"
    if m == "rand":
        return "rand10"
    return "all"


def validate_player_name(name: Any) -> Optional[str]:
    if name is None:
        return None
    s = str(name).strip()
    if not s:
        return None
    if len(s.encode("utf-8")) > 64:
        return None
    return s


def validate_score(score: Any) -> Optional[int]:
    try:
        v = int(score)
    except Exception:
        return None
    if v < 0 or v > 100:
        return None
    return v


def sort_leaderboard(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # score desc, createdAt desc
    return sorted(
        items,
        key=lambda x: (int(x.get("score") or 0), str(x.get("createdAt") or "")),
        reverse=True,
    )


def find_entity_set(list_key: str, entity_id: str) -> Optional[str]:
    for s in list_sets():
        sid = s["id"]
        try:
            meta = load_set_meta(sid)
        except Exception:
            continue
        for e in (meta.get(list_key) or []):
            if (e.get("id") or "") == entity_id:
                return sid
    return None


def split_by_id(items: List[Dict[str, Any]], entity_id: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    rest = []
    found = None
    for e in items:
        if found is None and (e.get("id") or "") == entity_id:
            found = e
        else:
            rest.append(e)
    return found, rest


@dataclass
class Cfg:
    docroot: Path


class Handler(BaseHTTPRequestHandler):
    server_version = "jaktpass-py/0.1"

    def _send_json(self, code: int, obj: Any, headers: Optional[List[Tuple[str, str]]] = None) -> None:
        b = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        if headers:
            for k, v in headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _ok(self, data: Any, code: int = 200) -> None:
        self._send_json(code, {"ok": True, "data": data})

    def _err(self, code: int, error: str, details: Any = None, headers: Optional[List[Tuple[str, str]]] = None) -> None:
        self._send_json(code, {"ok": False, "error": error, "details": details or {}}, headers=headers)

    def _require_admin(self) -> bool:
        user = getenv_default("JAKTPASS_ADMIN_USER", "admin")
        pw = getenv_default("JAKTPASS_ADMIN_PASS", "admin")
        auth = self.headers.get("Authorization")
        if not auth or not auth.startswith("Basic "):
            self._err(401, "unauthorized", "Missing or invalid Basic Auth", headers=[("WWW-Authenticate", 'Basic realm="jaktpass-admin"')])
            return False
        try:
            dec = base64.b64decode(auth[len("Basic ") :].encode("ascii")).decode("utf-8")
            u, p = dec.split(":", 1)
        except Exception:
            self._err(401, "unauthorized", "Missing or invalid Basic Auth", headers=[("WWW-Authenticate", 'Basic realm="jaktpass-admin"')])
            return False
        if u != user or p != pw:
            self._err(401, "unauthorized", "Missing or invalid Basic Auth", headers=[("WWW-Authenticate", 'Basic realm="jaktpass-admin"')])
            return False
        return True

    # -------------------------
    # V2 auth (cookie session)
    # -------------------------

    def _cookie_secure(self) -> bool:
        v = (getenv_default("JAKTPASS_COOKIE_SECURE", "false") or "").lower()
        return v in ("1", "true", "yes")

    def _get_cookie(self, name: str) -> Optional[str]:
        raw = self.headers.get("Cookie") or ""
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        for p in parts:
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            if k.strip() == name:
                return v.strip()
        return None

    def _v2_set_cookie(self, token: str) -> List[Tuple[str, str]]:
        base = f"{v2_cookie_name()}={token}; Path=/; HttpOnly; SameSite=Lax"
        if self._cookie_secure():
            base += "; Secure"
        return [("Set-Cookie", base)]

    def _v2_expire_cookie(self) -> List[Tuple[str, str]]:
        return [("Set-Cookie", f"{v2_cookie_name()}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")]

    def _v2_current_admin(self) -> Optional[Dict[str, Any]]:
        tok = self._get_cookie(v2_cookie_name())
        if not tok:
            return None
        sess = v2_load_session(tok)
        if not sess:
            return None
        admin_id = sess.get("adminId")
        if not admin_id:
            return None
        try:
            return v2_load_admin(str(admin_id))
        except Exception:
            return None

    def _v2_require_admin(self) -> Optional[Dict[str, Any]]:
        adm = self._v2_current_admin()
        if not adm:
            self._err(401, "unauthorized", {"details": "Not logged in"})
            return None
        return adm

    def _read_json_body(self) -> Optional[Dict[str, Any]]:
        try:
            n = int(self.headers.get("Content-Length") or "0")
        except Exception:
            n = 0
        b = self.rfile.read(n) if n else b""
        try:
            obj = json.loads(b.decode("utf-8") or "{}")
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    def _read_multipart(self) -> Optional[Dict[str, Tuple[str, bytes]]]:
        ct = self.headers.get("Content-Type") or ""
        m = re.match(r"multipart/form-data;\s*boundary=(.+)", ct)
        if not m:
            return None
        boundary = m.group(1).strip().strip('"')
        try:
            n = int(self.headers.get("Content-Length") or "0")
        except Exception:
            n = 0
        body = self.rfile.read(n) if n else b""
        # Minimal multipart parsing (enough for one file field)
        parts: Dict[str, Tuple[str, bytes]] = {}
        delim = ("--" + boundary).encode("utf-8")
        for chunk in body.split(delim):
            chunk = chunk.strip()
            if not chunk or chunk == b"--":
                continue
            if chunk.startswith(b"--"):
                continue
            if chunk.startswith(b"\r\n"):
                chunk = chunk[2:]
            header_blob, _, content = chunk.partition(b"\r\n\r\n")
            content = content.rstrip(b"\r\n")
            msg = email.message_from_bytes(header_blob)
            cd = msg.get("Content-Disposition") or ""
            # name="file"; filename="x.png"
            nm = re.search(r'name="([^"]+)"', cd)
            fnm = re.search(r'filename="([^"]+)"', cd)
            if not nm:
                continue
            name = nm.group(1)
            filename = fnm.group(1) if fnm else ""
            parts[name] = (filename, content)
        return parts

    def _serve_static(self, cfg: Cfg, url_path: str) -> None:
        # History fallback: okänd path -> index.html
        p = urlparse(url_path).path
        if p == "/":
            rel = "index.html"
        else:
            rel = p.lstrip("/")
        fs = (cfg.docroot / rel).resolve()
        if not str(fs).startswith(str(cfg.docroot.resolve())):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if fs.is_dir():
            fs = fs / "index.html"
        if not fs.exists():
            fs = (cfg.docroot / "index.html")
        b = fs.read_bytes()
        ct = content_type_from_filename(fs.name)
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self) -> None:
        cfg: Cfg = self.server.cfg  # type: ignore[attr-defined]
        u = urlparse(self.path)
        path = u.path
        if path.startswith("/api/"):
            return self._handle_api("GET", path, u)
        return self._serve_static(cfg, self.path)

    def do_POST(self) -> None:
        u = urlparse(self.path)
        if u.path.startswith("/api/"):
            return self._handle_api("POST", u.path, u)
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_PATCH(self) -> None:
        u = urlparse(self.path)
        if u.path.startswith("/api/"):
            return self._handle_api("PATCH", u.path, u)
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        u = urlparse(self.path)
        if u.path.startswith("/api/"):
            return self._handle_api("DELETE", u.path, u)
        self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_api(self, method: str, path: str, u) -> None:
        # Routing
        segs = [s for s in path.split("/") if s]
        # segs starts with "api"
        segs = segs[1:]

        try:
            # -------------------------
            # V2 (multi-admin)
            # -------------------------
            if segs and segs[0] == "v2":
                v2 = segs[1:]

                if method == "POST" and v2 == ["register"]:
                    body = self._read_json_body()
                    if body is None:
                        return self._err(400, "invalid_json", {})
                    email = validate_email(body.get("email"))
                    pw = validate_password(body.get("password"))
                    if not email:
                        return self._err(400, "invalid_email", {})
                    if not pw:
                        return self._err(400, "invalid_password", {"details": "minst 8 tecken"})
                    with V2_LOCK:
                        idx = v2_index_load()
                        if email in idx:
                            return self._err(409, "email_taken", {})
                        admin_id = uuid_v4()
                        salt = os.urandom(16)
                        h = pbkdf2_sha256(pw, salt)
                        admin = {
                            "id": admin_id,
                            "email": email,
                            "pw": {
                                "alg": "pbkdf2_sha256",
                                "iter": 100000,
                                "salt": base64.b64encode(salt).decode("ascii"),
                                "hash": base64.b64encode(h).decode("ascii"),
                            },
                            "createdAt": now_rfc3339(),
                        }
                        v2_save_admin(admin_id, admin)
                        idx[email] = admin_id
                        v2_index_save(idx)
                        tok = v2_new_session(admin_id)
                    return self._send_json(201, {"ok": True, "data": {"admin": {"id": admin_id, "email": email}}}, headers=self._v2_set_cookie(tok))

                if method == "POST" and v2 == ["login"]:
                    body = self._read_json_body()
                    if body is None:
                        return self._err(400, "invalid_json", {})
                    email = validate_email(body.get("email"))
                    pw = validate_password(body.get("password"))
                    if not email or not pw:
                        return self._err(401, "unauthorized", {})
                    with V2_LOCK:
                        idx = v2_index_load()
                        admin_id = idx.get(email)
                    if not admin_id:
                        return self._err(401, "unauthorized", {})
                    try:
                        admin = v2_load_admin(admin_id)
                        salt = base64.b64decode((admin.get("pw") or {}).get("salt") or "")
                        want = base64.b64decode((admin.get("pw") or {}).get("hash") or "")
                        got = pbkdf2_sha256(pw, salt)
                        if got != want:
                            return self._err(401, "unauthorized", {})
                        tok = v2_new_session(admin_id)
                        return self._send_json(200, {"ok": True, "data": {"admin": {"id": admin_id, "email": email}}}, headers=self._v2_set_cookie(tok))
                    except Exception:
                        return self._err(401, "unauthorized", {})

                if method == "POST" and v2 == ["logout"]:
                    tok = self._get_cookie(v2_cookie_name())
                    if tok:
                        v2_delete_session(tok)
                    return self._send_json(200, {"ok": True, "data": {"loggedOut": True}}, headers=self._v2_expire_cookie())

                if method == "GET" and v2 == ["me"]:
                    adm = self._v2_current_admin()
                    if not adm:
                        return self._err(401, "unauthorized", {})
                    return self._ok({"admin": {"id": adm.get("id"), "email": adm.get("email"), "createdAt": adm.get("createdAt")}})

                # Admin-only v2 endpoints
                if v2 and v2[0] == "sets":
                    adm = self._v2_require_admin()
                    if not adm:
                        return
                    admin_id = str(adm.get("id") or "")

                    if method == "GET" and v2 == ["sets"]:
                        root = v2_admin_sets_dir(admin_id)
                        root.mkdir(parents=True, exist_ok=True)
                        out = []
                        for sid in sorted([p.name for p in root.iterdir() if p.is_dir()]):
                            try:
                                meta = v2_load_set_meta(admin_id, sid)
                            except Exception:
                                continue
                            img = (meta.get("image") or {}).get("filename")
                            out.append({"id": sid, "name": (meta.get("set") or {}).get("name"), "hasImage": bool(img), "shareId": meta.get("shareId")})
                        return self._ok(out)

                    if method == "POST" and v2 == ["sets"]:
                        body = self._read_json_body()
                        if body is None:
                            return self._err(400, "invalid_json", {})
                        nm = validate_nonempty_string(body.get("name"))
                        if not nm:
                            return self._err(400, "invalid_name", {})
                        set_id = uuid_v4()
                        share_id = v2_new_share(admin_id, set_id)
                        meta = {"set": {"id": set_id, "name": nm, "createdAt": now_rfc3339()}, "image": None, "stands": [], "shareId": share_id}
                        v2_save_set_meta(admin_id, set_id, meta)
                        return self._ok({"id": set_id, "shareId": share_id, "shareUrl": f"/v2/#/quiz/{share_id}"}, code=201)

                    if method == "GET" and len(v2) == 2 and v2[0] == "sets":
                        set_id = unquote(v2[1])
                        if not validate_set_id(set_id):
                            return self._err(400, "invalid_set_id", {"setId": set_id})
                        try:
                            meta = v2_load_set_meta(admin_id, set_id)
                        except FileNotFoundError:
                            return self._err(404, "set_not_found", {"setId": set_id})
                        except Exception as e:
                            return self._err(500, "failed_to_load_set", {"error": str(e)})
                        share_id = meta.get("shareId")
                        img = (meta.get("image") or {}).get("filename")
                        meta["imageUrl"] = (f"/api/v2/media/shares/{share_id}/image" if (share_id and img) else None)
                        return self._ok(meta)

                    if method == "DELETE" and len(v2) == 2 and v2[0] == "sets":
                        set_id = unquote(v2[1])
                        if not validate_set_id(set_id):
                            return self._err(400, "invalid_set_id", {"setId": set_id})
                        try:
                            meta = v2_load_set_meta(admin_id, set_id)
                        except FileNotFoundError:
                            return self._err(404, "set_not_found", {"setId": set_id})
                        except Exception as e:
                            return self._err(500, "failed_to_load_set", {"error": str(e)})

                        share_id = str(meta.get("shareId") or "")
                        try:
                            # Gör quiz-länken ogiltig
                            if share_id:
                                try:
                                    v2_share_path(share_id).unlink()
                                except FileNotFoundError:
                                    pass
                            # Ta bort hela set-mappen (meta, bild, leaderboard, etc)
                            import shutil
                            shutil.rmtree(v2_set_dir(admin_id, set_id), ignore_errors=True)
                        except Exception as e:
                            return self._err(500, "failed_to_delete_set", {"error": str(e)})
                        return self._ok({"deleted": True, "setId": set_id, "shareId": share_id})

                    if method == "POST" and len(v2) == 3 and v2[0] == "sets" and v2[2] == "image":
                        set_id = unquote(v2[1])
                        if not validate_set_id(set_id):
                            return self._err(400, "invalid_set_id", {"setId": set_id})
                        try:
                            meta = v2_load_set_meta(admin_id, set_id)
                        except FileNotFoundError:
                            return self._err(404, "set_not_found", {"setId": set_id})
                        parts = self._read_multipart()
                        if not parts or "file" not in parts:
                            return self._err(400, "invalid_multipart", {"details": "missing file"})
                        filename, data = parts["file"]
                        ext = image_ext(filename or "")
                        if not ext:
                            return self._err(400, "invalid_image_extension", {"allowed": ["png", "jpg", "jpeg", "webp"]})
                        out_name = f"image.{ext}"
                        out_path = v2_set_dir(admin_id, set_id) / out_name
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        out_path.write_bytes(data)
                        w, h = image_dims(ext, data)
                        meta["image"] = {"filename": out_name, "width": w, "height": h, "uploadedAt": now_rfc3339()}
                        v2_save_set_meta(admin_id, set_id, meta)
                        return self._ok(meta["image"])

                    if method == "POST" and len(v2) == 3 and v2[0] == "sets" and v2[2] == "stands":
                        set_id = unquote(v2[1])
                        if not validate_set_id(set_id):
                            return self._err(400, "invalid_set_id", {"setId": set_id})
                        body = self._read_json_body()
                        if body is None:
                            return self._err(400, "invalid_json", {})
                        stand_id = (body.get("id") or "").strip()
                        if stand_id and not validate_set_id(stand_id):
                            return self._err(400, "invalid_stand_id", {"standId": stand_id})
                        name = validate_nonempty_string(body.get("name"))
                        x = clamp01(body.get("x"))
                        y = clamp01(body.get("y"))
                        note = body.get("note")
                        sym = validate_symbol(body.get("symbol"))
                        if not name or x is None or y is None:
                            return self._err(400, "invalid_payload", {"expected": "name + x + y (0..1)"})
                        try:
                            meta = v2_load_set_meta(admin_id, set_id)
                        except FileNotFoundError:
                            return self._err(404, "set_not_found", {"setId": set_id})
                        now = now_rfc3339()
                        stands0 = meta.get("stands") or []
                        if stand_id and any((s or {}).get("id") == stand_id for s in stands0):
                            return self._err(409, "stand_id_taken", {"standId": stand_id})
                        stand = {"id": (stand_id or uuid_v4()), "name": name, "x": x, "y": y, "symbol": sym, "createdAt": now, "updatedAt": now}
                        if note is not None:
                            stand["note"] = str(note)
                        meta["stands"] = [stand] + stands0
                        v2_save_set_meta(admin_id, set_id, meta)
                        return self._ok(stand, code=201)

                    if method in ("PATCH", "DELETE") and len(v2) == 4 and v2[0] == "sets" and v2[2] == "stands":
                        set_id = unquote(v2[1])
                        stand_id = unquote(v2[3])
                        if not validate_set_id(set_id):
                            return self._err(400, "invalid_set_id", {"setId": set_id})
                        try:
                            meta = v2_load_set_meta(admin_id, set_id)
                        except FileNotFoundError:
                            return self._err(404, "set_not_found", {"setId": set_id})
                        stands = meta.get("stands") or []
                        found, rest = split_by_id(stands, stand_id)
                        if not found:
                            return self._err(404, "not_found", {"id": stand_id})
                        if method == "DELETE":
                            meta["stands"] = rest
                            v2_save_set_meta(admin_id, set_id, meta)
                            return self._ok({"deleted": True})
                        body = self._read_json_body()
                        if body is None:
                            return self._err(400, "invalid_json", {})
                        if "name" in body:
                            nm2 = validate_nonempty_string(body.get("name"))
                            if not nm2:
                                return self._err(400, "invalid_payload", {"details": "name: invalid"})
                            found["name"] = nm2
                        if "x" in body:
                            xv = clamp01(body.get("x"))
                            if xv is None:
                                return self._err(400, "invalid_payload", {"details": "x: out_of_range"})
                            found["x"] = xv
                        if "y" in body:
                            yv = clamp01(body.get("y"))
                            if yv is None:
                                return self._err(400, "invalid_payload", {"details": "y: out_of_range"})
                            found["y"] = yv
                        if "note" in body:
                            found["note"] = str(body.get("note") or "")
                        if "symbol" in body:
                            found["symbol"] = validate_symbol(body.get("symbol"))
                        found["updatedAt"] = now_rfc3339()
                        meta["stands"] = [found] + rest
                        v2_save_set_meta(admin_id, set_id, meta)
                        return self._ok(found)

                    if method == "POST" and len(v2) == 3 and v2[2] == "share":
                        set_id = unquote(v2[1])
                        if not validate_set_id(set_id):
                            return self._err(400, "invalid_set_id", {"setId": set_id})
                        meta = v2_load_set_meta(admin_id, set_id)
                        share_id = meta.get("shareId") or ""
                        if not share_id:
                            share_id = v2_new_share(admin_id, set_id)
                            meta["shareId"] = share_id
                            v2_save_set_meta(admin_id, set_id, meta)
                            return self._ok({"shareId": share_id, "shareUrl": f"/v2/#/quiz/{share_id}"}, code=201)
                        return self._ok({"shareId": share_id, "shareUrl": f"/v2/#/quiz/{share_id}"})

                # Public quiz/media
                if method == "GET" and len(v2) == 2 and v2[0] == "quiz":
                    share_id = unquote(v2[1])
                    qs = parse_qs(u.query or "")
                    mode = normalize_mode((qs.get("mode") or ["rand10"])[0])
                    share = v2_load_share(share_id)
                    if not share:
                        return self._err(404, "share_not_found", {})
                    admin_id = str(share.get("adminId"))
                    set_id = str(share.get("setId"))
                    meta = v2_load_set_meta(admin_id, set_id)
                    stands = meta.get("stands") or []
                    n0 = len(stands)
                    if mode == "all":
                        count = n0
                    elif mode == "randHalf":
                        count = (n0 + 1) // 2
                    else:
                        count = 10
                    sample = shuffle_take(stands, count)
                    visible = [{"id": s.get("id"), "x": s.get("x"), "y": s.get("y"), "symbol": s.get("symbol") or "dot"} for s in sample]
                    questions = [{"standId": s.get("id"), "name": s.get("name")} for s in sample]
                    return self._ok({"mode": mode, "set": {"id": set_id, "name": (meta.get("set") or {}).get("name")}, "imageUrl": f"/api/v2/media/shares/{share_id}/image", "visibleStands": visible, "questions": questions})

                if len(v2) == 3 and v2[0] == "quiz" and v2[2] == "leaderboard":
                    share_id = unquote(v2[1])
                    if method == "GET":
                        qs = parse_qs(u.query or "")
                        mode = normalize_mode((qs.get("mode") or ["all"])[0])
                        share = v2_load_share(share_id)
                        if not share:
                            return self._err(404, "share_not_found", {})
                        admin_id = str(share.get("adminId"))
                        set_id = str(share.get("setId"))
                        items = v2_load_leaderboard(admin_id, set_id)
                        items = [i for i in items if (i.get("mode") or "all") == mode]
                        items = sort_leaderboard(items)[:20]
                        return self._ok({"mode": mode, "items": items})

                    if method == "POST":
                        body = self._read_json_body()
                        if body is None:
                            return self._err(400, "invalid_json", {})
                        name = validate_nonempty_string(body.get("name"))
                        try:
                            score = int(body.get("score"))
                        except Exception:
                            return self._err(400, "invalid_score", {})
                        mode = normalize_mode(str(body.get("mode") or "all"))
                        if not name:
                            return self._err(400, "invalid_name", {})
                        if score < 0 or score > 100:
                            return self._err(400, "invalid_score", {})
                        share = v2_load_share(share_id)
                        if not share:
                            return self._err(404, "share_not_found", {})
                        admin_id = str(share.get("adminId"))
                        set_id = str(share.get("setId"))
                        item = {"name": name, "score": score, "mode": mode, "createdAt": now_rfc3339()}
                        with V2_LOCK:
                            items = v2_load_leaderboard(admin_id, set_id)
                            items = sort_leaderboard([item] + (items or []))[:200]
                            try:
                                v2_save_leaderboard(admin_id, set_id, items)
                            except Exception as e:
                                return self._err(500, "failed_to_save_leaderboard", {"error": str(e)})
                        top = [i for i in items if (i.get("mode") or "all") == mode][:20]
                        return self._ok({"saved": True, "mode": mode, "items": top}, code=201)

                if method == "GET" and len(v2) == 4 and v2[:2] == ["media", "shares"] and v2[3] == "image":
                    share_id = unquote(v2[2])
                    share = v2_load_share(share_id)
                    if not share:
                        return self._err(404, "share_not_found", {})
                    admin_id = str(share.get("adminId"))
                    set_id = str(share.get("setId"))
                    meta = v2_load_set_meta(admin_id, set_id)
                    img = (meta.get("image") or {}).get("filename")
                    if not img:
                        return self._err(404, "image_not_found", {})
                    fp = v2_set_dir(admin_id, set_id) / img
                    if not fp.exists():
                        return self._err(404, "image_not_found", {})
                    b = fp.read_bytes()
                    ct = content_type_from_filename(fp.name)
                    self.send_response(200)
                    self.send_header("Content-Type", ct)
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return

                return self._err(404, "not_found", {"path": path})

            # Public
            if method == "GET" and segs == ["sets"]:
                return self._ok(list_sets())

            if method == "GET" and len(segs) == 2 and segs[0] == "sets":
                set_id = unquote(segs[1])
                if not validate_set_id(set_id):
                    return self._err(400, "invalid_set_id", {"setId": set_id})
                try:
                    meta = load_set_meta(set_id)
                except FileNotFoundError:
                    return self._err(404, "set_not_found", {"setId": set_id})
                image = meta.get("image") or None
                if image and image.get("filename"):
                    meta["imageUrl"] = f"/api/media/sets/{set_id}/image"
                else:
                    meta["imageUrl"] = None
                return self._ok(meta)

            if method == "GET" and len(segs) == 3 and segs[0] == "sets" and segs[2] == "quiz":
                set_id = unquote(segs[1])
                if not validate_set_id(set_id):
                    return self._err(400, "invalid_set_id", {"setId": set_id})
                qs = parse_qs(u.query or "")
                mode = (qs.get("mode") or ["rand10"])[0]
                try:
                    meta = load_set_meta(set_id)
                except FileNotFoundError:
                    return self._err(404, "set_not_found", {"setId": set_id})
                stands = meta.get("stands") or []
                # Quiz-modes: 10 slump, halva slump, eller alla
                n0 = len(stands)
                if mode in ("all",):
                    count = n0
                elif mode in ("randHalf", "half"):
                    count = (n0 + 1) // 2
                else:
                    count = 10
                sample = shuffle_take(stands, count)
                visible_dots = [{"id": s.get("id"), "x": s.get("x"), "y": s.get("y")} for s in sample]
                questions = [{"standId": s.get("id"), "name": s.get("name")} for s in sample]
                return self._ok({"visibleStands": visible_dots, "questions": questions})

            if method == "GET" and len(segs) == 3 and segs[0] == "sets" and segs[2] == "leaderboard":
                set_id = unquote(segs[1])
                if not validate_set_id(set_id):
                    return self._err(400, "invalid_set_id", {"setId": set_id})
                qs = parse_qs(u.query or "")
                mode = normalize_mode((qs.get("mode") or ["all"])[0])
                with with_set_lock(set_id):
                    items = load_leaderboard(set_id)
                items = [i for i in items if (i.get("mode") or "all") == mode]
                items = sort_leaderboard(items)[:20]
                return self._ok({"mode": mode, "items": items})

            if method == "POST" and len(segs) == 3 and segs[0] == "sets" and segs[2] == "leaderboard":
                set_id = unquote(segs[1])
                if not validate_set_id(set_id):
                    return self._err(400, "invalid_set_id", {"setId": set_id})
                body = self._read_json_body()
                if body is None:
                    return self._err(400, "invalid_json", {})
                name = validate_player_name(body.get("name"))
                score = validate_score(body.get("score"))
                mode = normalize_mode(body.get("mode") or "all")
                if not name:
                    return self._err(400, "invalid_name", {"details": "missing/empty/too_long"})
                if score is None:
                    return self._err(400, "invalid_score", {"details": "0..100"})
                item = {"name": name, "score": score, "mode": mode, "createdAt": now_rfc3339()}
                with with_set_lock(set_id):
                    items = load_leaderboard(set_id)
                    items = sort_leaderboard([item] + (items or []))[:200]
                    try:
                        save_leaderboard(set_id, items)
                    except Exception as e:
                        return self._err(500, "failed_to_save_leaderboard", {"error": str(e)})
                top = [i for i in items if (i.get("mode") or "all") == mode][:20]
                return self._ok({"saved": True, "mode": mode, "items": top}, code=201)

            if method == "GET" and segs[:4] == ["media", "sets", segs[2] if len(segs) > 2 else "", "image"]:
                if len(segs) != 4:
                    return self._err(404, "not_found", {})
                set_id = unquote(segs[2])
                if not validate_set_id(set_id):
                    return self._err(400, "invalid_set_id", {"setId": set_id})
                try:
                    meta = load_set_meta(set_id)
                except FileNotFoundError:
                    return self._err(404, "set_not_found", {"setId": set_id})
                img = (meta.get("image") or {}).get("filename")
                if not img:
                    return self._err(404, "image_not_found", {"setId": set_id})
                fp = set_dir(set_id) / img
                if not fp.exists():
                    return self._err(404, "image_not_found", {"setId": set_id})
                b = fp.read_bytes()
                ct = content_type_from_filename(fp.name)
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
                return

            # Admin
            if segs and segs[0] == "admin":
                if not self._require_admin():
                    return

            if method == "GET" and segs == ["admin", "ping"]:
                return self._ok({"authenticated": True})

            if method == "POST" and segs == ["admin", "sets"]:
                body = self._read_json_body()
                if body is None:
                    return self._err(400, "invalid_json", {})
                name = validate_nonempty_string(body.get("name"))
                if not name:
                    return self._err(400, "invalid_name", {"details": "missing/empty"})
                set_id = uuid_v4()
                meta = {
                    "set": {"id": set_id, "name": name, "createdAt": now_rfc3339()},
                    "image": None,
                    "stands": [],
                }
                save_set_meta(set_id, meta)
                return self._ok({"id": set_id}, code=201)

            if method == "DELETE" and len(segs) == 3 and segs[:2] == ["admin", "sets"]:
                set_id = unquote(segs[2])
                if not validate_set_id(set_id):
                    return self._err(400, "invalid_set_id", {"setId": set_id})
                with with_set_lock(set_id):
                    d = set_dir(set_id)
                    if not d.exists() or not d.is_dir():
                        return self._err(404, "set_not_found", {"setId": set_id})
                    try:
                        shutil.rmtree(d)
                    except Exception as e:
                        return self._err(500, "failed_to_delete_set", {"error": str(e)})
                return self._ok({"deleted": True, "setId": set_id})

            if method == "POST" and len(segs) == 4 and segs[:2] == ["admin", "sets"] and segs[3] == "image":
                set_id = unquote(segs[2])
                if not validate_set_id(set_id):
                    return self._err(400, "invalid_set_id", {"setId": set_id})
                with with_set_lock(set_id):
                    try:
                        meta = load_set_meta(set_id)
                    except FileNotFoundError:
                        return self._err(404, "set_not_found", {"setId": set_id})
                    parts = self._read_multipart()
                    if not parts or "file" not in parts:
                        return self._err(400, "invalid_multipart", {"details": "missing file"})
                    filename, data = parts["file"]
                    ext = image_ext(filename or "")
                    if not ext:
                        return self._err(400, "invalid_image_extension", {"allowed": ["png", "jpg", "jpeg", "webp"]})
                    out_name = f"image.{ext}"
                    out_path = set_dir(set_id) / out_name
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_bytes(data)
                    w, h = image_dims(ext, data)
                    meta["image"] = {
                        "filename": out_name,
                        "width": w,
                        "height": h,
                        "uploadedAt": now_rfc3339(),
                    }
                    save_set_meta(set_id, meta)
                    return self._ok(meta["image"])

            if method == "POST" and len(segs) == 4 and segs[:2] == ["admin", "sets"] and segs[3] == "stands":
                set_id = unquote(segs[2])
                if not validate_set_id(set_id):
                    return self._err(400, "invalid_set_id", {"setId": set_id})
                body = self._read_json_body()
                if body is None:
                    return self._err(400, "invalid_json", {})
                name = validate_nonempty_string(body.get("name"))
                x = clamp01(body.get("x"))
                y = clamp01(body.get("y"))
                note = body.get("note")
                sym = validate_symbol(body.get("symbol"))
                if not name or x is None or y is None:
                    return self._err(400, "invalid_payload", {"expected": "name + x + y (0..1)"})
                with with_set_lock(set_id):
                    try:
                        meta = load_set_meta(set_id)
                    except FileNotFoundError:
                        return self._err(404, "set_not_found", {"setId": set_id})
                    now = now_rfc3339()
                    stand = {"id": uuid_v4(), "name": name, "x": x, "y": y, "symbol": sym, "createdAt": now, "updatedAt": now}
                    if note is not None:
                        stand["note"] = str(note)
                    meta["stands"] = [stand] + (meta.get("stands") or [])
                    save_set_meta(set_id, meta)
                    return self._ok(stand, code=201)

            if method in ("PATCH", "DELETE") and len(segs) == 3 and segs[:2] == ["admin", "stands"]:
                stand_id = unquote(segs[2])
                set_id = find_entity_set("stands", stand_id)
                if not set_id:
                    return self._err(404, "not_found", {"id": stand_id})
                with with_set_lock(set_id):
                    meta = load_set_meta(set_id)
                    stands = meta.get("stands") or []
                    found, rest = split_by_id(stands, stand_id)
                    if not found:
                        return self._err(404, "not_found", {"id": stand_id})
                    if method == "DELETE":
                        meta["stands"] = rest
                        save_set_meta(set_id, meta)
                        return self._ok({"deleted": True})
                    body = self._read_json_body()
                    if body is None:
                        return self._err(400, "invalid_json", {})
                    # strict: present but invalid -> 400
                    if "name" in body:
                        nm = validate_nonempty_string(body.get("name"))
                        if not nm:
                            return self._err(400, "invalid_payload", {"details": "name: invalid"})
                        found["name"] = nm
                    if "x" in body:
                        xv = clamp01(body.get("x"))
                        if xv is None:
                            return self._err(400, "invalid_payload", {"details": "x: out_of_range"})
                        found["x"] = xv
                    if "y" in body:
                        yv = clamp01(body.get("y"))
                        if yv is None:
                            return self._err(400, "invalid_payload", {"details": "y: out_of_range"})
                        found["y"] = yv
                    if "note" in body:
                        found["note"] = str(body.get("note") or "")
                    found["updatedAt"] = now_rfc3339()
                    meta["stands"] = [found] + rest
                    save_set_meta(set_id, meta)
                    return self._ok(found)

            # NOTE: areas (områden) är borttagna i denna variant.

            return self._err(404, "not_found", {"path": path})
        except Exception as e:
            return self._err(500, "internal_error", {"error": str(e)})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--docroot", default=str((Path(__file__).resolve().parents[1] / "priv" / "www").resolve()))
    args = ap.parse_args()

    sets_dir().mkdir(parents=True, exist_ok=True)

    cfg = Cfg(docroot=Path(args.docroot).resolve())
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.cfg = cfg  # type: ignore[attr-defined]
    print(f"jaktpass python server: http://{args.host}:{args.port}  (docroot={cfg.docroot})")
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


