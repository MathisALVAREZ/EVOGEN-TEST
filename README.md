# -*- coding: utf-8 -*-
"""Graylog Permission Manager — UI redesign with dark industrial theme."""

import base64
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont
import requests
import urllib3
import json
from urllib.parse import quote

try:
    from secret import GRAYLOG_URL_PROD, GRAYLOG_URL_RECETTE, GRAYLOG_USERNAME, GRAYLOG_PASSWORD
except ImportError:
    raise SystemExit(
        "Fichier 'secret.py' introuvable.\n"
        "Créez-le avec GRAYLOG_URL_PROD, GRAYLOG_URL_RECETTE, GRAYLOG_USERNAME, GRAYLOG_PASSWORD."
    )

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── Constantes ───────────────────────────────────────────────────────────────
PERMISSIONS:     List[str] = ["view", "manage", "own"]
GRN_PREFIX:      str       = "grn::::stream:"
GRN_USER_PREFIX: str       = "grn::::user:"
CATEGORY_RE                = re.compile(r"^\[([^\]#][^\]]*)\]")   # exclut [#...]

# ─── Palette ──────────────────────────────────────────────────────────────────
C = {
    "bg":          "#0d0f14",
    "bg2":         "#13161e",
    "bg3":         "#1a1e2a",
    "bg4":         "#222736",
    "border":      "#2a2f3d",
    "border2":     "#353c52",
    "cyan":        "#00e5ff",
    "cyan_dim":    "#00b8cc",
    "cyan_dark":   "#003a42",
    "green":       "#00ff9d",
    "green_dark":  "#003d26",
    "red":         "#ff4757",
    "red_dark":    "#3d0a10",
    "orange":      "#ffa502",
    "orange_dark": "#3d2800",
    "yellow":      "#ffd32a",
    "text":        "#e8ecf4",
    "text2":       "#8891a8",
    "text3":       "#555e73",
    "prod":        "#00ff9d",
    "recette":     "#ffa502",
    "select":      "#1a2a35",
    "select2":     "#0a1a20",
}


# ─── Client API ───────────────────────────────────────────────────────────────

class GraylogClient:
    def __init__(self, url: str) -> None:
        self.base_url = url.rstrip("/")
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers.update(self._make_headers())

    def _make_headers(self) -> Dict[str, str]:
        creds = f"{GRAYLOG_USERNAME}:{GRAYLOG_PASSWORD}"
        b64   = base64.b64encode(creds.encode()).decode()
        return {
            "Authorization": f"Basic {b64}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
            "X-Requested-By": "graylog-manager",
        }

    def _req(self, method: str, path: str, **kw) -> Optional[Dict]:
        url = f"{self.base_url}{path}"
        try:
            r = self.session.request(method, url, timeout=15, **kw)
            r.raise_for_status()
            return {} if (r.status_code == 204 or not r.content) else r.json()
        except requests.HTTPError as e:
            body = e.response.text[:400] if e.response is not None else ""
            logger.error("%s %s → %s: %s", method.upper(), url, e.response.status_code, body)
            return None
        except requests.RequestException as e:
            logger.error("%s %s → %s", method.upper(), url, e)
            return None

    def get_streams(self) -> Dict[str, str]:
        d = self._req("get", "/api/streams")
        return {s["id"]: s.get("title", "?") for s in (d or {}).get("streams", [])}

    def get_users(self) -> List[Dict[str, str]]:
        d = self._req("get", "/api/users")
        return [
            {"id": u["id"], "username": u.get("username",""), "full_name": u.get("full_name","")}
            for u in (d or {}).get("users", [])
        ]

    def get_user_permissions(self, uid: str) -> Dict[str, Any]:
        return self._req("get", f"/api/authz/shares/user/{uid}") or {}

    def user_perm_on_stream(self, perms: Dict, sid: str) -> Optional[str]:
        return perms.get("context",{}).get("grantee_capabilities",{}).get(f"{GRN_PREFIX}{sid}")

    def get_stream_grantees(self, stream_id: str) -> Dict[str, str]:
        """
        Retourne {user_grn: capability} pour un stream donné.
        Utilise POST .../prepare pour lire l'état actuel.
        """
        grn = f"{GRN_PREFIX}{stream_id}"
        enc = quote(grn, safe="")
        url = f"{self.base_url}/api/authz/shares/entities/{enc}/prepare"
        try:
            r = self.session.post(url, json={}, timeout=15)
            if r.status_code in (200, 201):
                data = r.json()
                return data.get("selected_grantee_capabilities") or data.get("grantees") or {}
        except Exception as e:
            logger.error("get_stream_grantees: %s", e)
        return {}

    def _prepare(self, stream_grn: str) -> Optional[Dict]:
        enc = quote(stream_grn, safe="")
        url = f"{self.base_url}/api/authz/shares/entities/{enc}/prepare"
        try:
            r = self.session.post(url, json={}, timeout=15)
            return r.json() if r.status_code in (200,201) else None
        except Exception as e:
            logger.error("prepare: %s", e)
            return None

    def _post_shares(self, stream_grn: str, grantees: Dict[str, str]) -> Tuple[bool, str]:
        enc = quote(stream_grn, safe="")
        url = f"{self.base_url}/api/authz/shares/entities/{enc}"
        try:
            r = self.session.post(url, json={"selected_grantee_capabilities": grantees}, timeout=15)
            return (True, "OK") if r.status_code in (200,201,204) else (False, f"HTTP {r.status_code}: {r.text[:300]}")
        except Exception as e:
            return False, str(e)

    def set_permission(self, sid: str, uid: str, cap: str) -> Tuple[bool, str]:
        grn  = f"{GRN_PREFIX}{sid}"
        ugrn = f"{GRN_USER_PREFIX}{uid}"
        p    = self._prepare(grn)
        if p is None:
            return False, "prepare failed"
        existing = dict(p.get("selected_grantee_capabilities") or p.get("grantees") or {})
        existing[ugrn] = cap
        ok, msg = self._post_shares(grn, existing)
        return (True, f"OK — {cap}") if ok else (False, msg)

    def remove_permission(self, sid: str, uid: str) -> Tuple[bool, str]:
        grn  = f"{GRN_PREFIX}{sid}"
        ugrn = f"{GRN_USER_PREFIX}{uid}"
        p    = self._prepare(grn)
        if p is None:
            return False, "prepare failed"
        existing = {k:v for k,v in (p.get("selected_grantee_capabilities") or p.get("grantees") or {}).items() if k != ugrn}
        ok, msg  = self._post_shares(grn, existing)
        return (True, "Supprimé") if ok else (False, msg)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def extract_category(title: str) -> Optional[str]:
    m = CATEGORY_RE.match(title.strip())
    return m.group(1).strip() if m else None

def perm_color(perm: str) -> str:
    return {"view": C["cyan"], "manage": C["orange"], "own": C["red"]}.get(perm, C["text2"])

def perm_icon(perm: str) -> str:
    return {"view": "👁", "manage": "⚙", "own": "👑"}.get(perm, "?")


# ─── Widgets personnalisés ─────────────────────────────────────────────────────

class DarkTooltip:
    """Tooltip sombre qui apparaît au survol."""
    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text   = text
        self.tw: Optional[tk.Toplevel] = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _=None) -> None:
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self.tw, text=self.text,
            background=C["bg4"], foreground=C["cyan"],
            relief="flat", padx=8, pady=4,
            font=("Consolas", 9),
        ).pack()

    def _hide(self, _=None) -> None:
        if self.tw:
            self.tw.destroy()
            self.tw = None


# ─── Fenêtre : détail d'un stream ─────────────────────────────────────────────

class StreamDetailWindow(tk.Toplevel):
    """Fenêtre popup affichant les droits de tous les utilisateurs sur un stream."""

    def __init__(self, parent, stream_title: str, stream_id: str,
                 client: GraylogClient, users: List[Dict[str,str]]) -> None:
        super().__init__(parent)
        self.title(f"Droits — {stream_title}")
        self.configure(bg=C["bg"])
        self.resizable(True, True)
        self.geometry("620x480")
        self.grab_set()

        # Construire un index GRN→username
        self._grn_to_name: Dict[str,str] = {
            f"{GRN_USER_PREFIX}{u['id']}": u["username"] for u in users
        }

        self._build(stream_title, stream_id, client)

    def _build(self, title: str, sid: str, client: GraylogClient) -> None:
        # Titre
        hdr = tk.Frame(self, bg=C["bg2"], pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="DROITS DU STREAM", font=("Consolas", 9, "bold"),
                 fg=C["text3"], bg=C["bg2"]).pack()
        tk.Label(hdr, text=title, font=("Consolas", 15, "bold"),
                 fg=C["cyan"], bg=C["bg2"]).pack(pady=(2,0))

        sep = tk.Frame(self, bg=C["cyan"], height=1)
        sep.pack(fill="x")

        # Zone scrollable
        container = tk.Frame(self, bg=C["bg"])
        container.pack(fill="both", expand=True, padx=16, pady=12)

        canvas   = tk.Canvas(container, bg=C["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.inner = tk.Frame(canvas, bg=C["bg"])
        self.inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Chargement
        self.loading_lbl = tk.Label(self.inner, text="⟳  Chargement…",
                                    font=("Consolas", 11), fg=C["text2"], bg=C["bg"])
        self.loading_lbl.pack(pady=40)

        threading.Thread(target=self._load, args=(sid, client), daemon=True).start()

    def _load(self, sid: str, client: GraylogClient) -> None:
        grantees = client.get_stream_grantees(sid)
        self.after(0, self._populate, grantees)

    def _populate(self, grantees: Dict[str, str]) -> None:
        self.loading_lbl.destroy()

        if not grantees:
            tk.Label(self.inner, text="Aucun droit explicite configuré.",
                     font=("Consolas", 11), fg=C["text3"], bg=C["bg"]).pack(pady=30)
            return

        # En-têtes
        hdr = tk.Frame(self.inner, bg=C["bg3"])
        hdr.pack(fill="x", pady=(0,4))
        tk.Label(hdr, text="UTILISATEUR", font=("Consolas", 9, "bold"),
                 fg=C["text3"], bg=C["bg3"], width=32, anchor="w", padx=8, pady=6).grid(row=0, column=0, sticky="w")
        tk.Label(hdr, text="PERMISSION", font=("Consolas", 9, "bold"),
                 fg=C["text3"], bg=C["bg3"], width=14, anchor="w", padx=8, pady=6).grid(row=0, column=1, sticky="w")

        # Trier : d'abord par cap (own > manage > view), puis par nom
        order = {"own":0,"manage":1,"view":2}
        sorted_g = sorted(grantees.items(), key=lambda x: (order.get(x[1],9), x[0]))

        for i, (grn, cap) in enumerate(sorted_g):
            name  = self._grn_to_name.get(grn, grn.split(":")[-1])
            color = perm_color(cap)
            icon  = perm_icon(cap)
            bg    = C["bg2"] if i % 2 == 0 else C["bg"]

            row = tk.Frame(self.inner, bg=bg)
            row.pack(fill="x")
            tk.Label(row, text=f"  {name}", font=("Consolas", 10),
                     fg=C["text"], bg=bg, width=32, anchor="w", pady=5).grid(row=0, column=0, sticky="w")
            tk.Label(row, text=f"{icon}  {cap}", font=("Consolas", 10, "bold"),
                     fg=color, bg=bg, width=14, anchor="w").grid(row=0, column=1, sticky="w")

        # Total
        sep = tk.Frame(self.inner, bg=C["border"], height=1)
        sep.pack(fill="x", pady=6)
        tk.Label(self.inner, text=f"{len(grantees)} entrée(s)",
                 font=("Consolas", 9), fg=C["text3"], bg=C["bg"]).pack(anchor="e", padx=12)


# ─── Application principale ───────────────────────────────────────────────────

class GraylogApp(tk.Tk):

    def __init__(self) -> None:
        super().__init__()
        self.title("Graylog Permission Manager")
        self.geometry("1400x900")
        self.minsize(1100, 700)
        self.configure(bg=C["bg"])

        # État
        self.env            = tk.StringVar(value="PROD")
        self.client         = GraylogClient(GRAYLOG_URL_PROD)
        self.streams:       Dict[str,str]          = {}
        self.stream_id_map: Dict[int,str]          = {}
        self.users:         List[Dict[str,str]]    = []
        self._user_id_map:  Dict[int,str]          = {}
        self.categories:    List[str]              = []
        self.sel_user_ids:  List[str]              = []
        self.perms_cache:   Dict[str,Dict]         = {}

        self._apply_ttk_theme()
        self._build_ui()
        self._load_data_async()

    # ── Thème ttk ─────────────────────────────────────────────────────────────

    def _apply_ttk_theme(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".",
            background=C["bg"], foreground=C["text"],
            fieldbackground=C["bg3"], troughcolor=C["bg2"],
            bordercolor=C["border"], darkcolor=C["bg2"], lightcolor=C["bg3"],
            selectbackground=C["cyan_dark"], selectforeground=C["cyan"],
            font=("Consolas", 10),
        )
        style.configure("TScrollbar",
            background=C["bg3"], troughcolor=C["bg2"],
            arrowcolor=C["text3"], bordercolor=C["border"],
        )
        style.map("TScrollbar", background=[("active", C["bg4"])])
        style.configure("TEntry",
            fieldbackground=C["bg3"], foreground=C["text"],
            insertcolor=C["cyan"], bordercolor=C["border"],
            padding=6,
        )
        style.map("TEntry", bordercolor=[("focus", C["cyan"])])
        style.configure("TRadiobutton",
            background=C["bg"], foreground=C["text2"],
            focuscolor="", indicatorcolor=C["bg3"],
        )
        style.map("TRadiobutton",
            foreground=[("selected", C["cyan"])],
            indicatorcolor=[("selected", C["cyan"])],
        )

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ══ HEADER BAR ════════════════════════════════════════════════════════
        header = tk.Frame(self, bg=C["bg2"], height=54)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        # Logo / titre
        logo_frame = tk.Frame(header, bg=C["bg2"])
        logo_frame.pack(side="left", padx=20, pady=8)
        tk.Label(logo_frame, text="⬡", font=("Consolas", 22, "bold"),
                 fg=C["cyan"], bg=C["bg2"]).pack(side="left")
        tk.Label(logo_frame, text=" GRAYLOG", font=("Consolas", 15, "bold"),
                 fg=C["text"], bg=C["bg2"]).pack(side="left")
        tk.Label(logo_frame, text=" PERMISSIONS", font=("Consolas", 15),
                 fg=C["cyan"], bg=C["bg2"]).pack(side="left")

        # Séparateur vertical
        tk.Frame(header, bg=C["border"], width=1).pack(side="left", fill="y", pady=10)

        # Switcher ENV
        env_frame = tk.Frame(header, bg=C["bg2"])
        env_frame.pack(side="left", padx=20)

        self.btn_prod    = self._env_button(env_frame, "PROD",    "●", C["prod"],    lambda: self._switch_env("PROD"))
        self.btn_recette = self._env_button(env_frame, "RECETTE", "●", C["recette"], lambda: self._switch_env("RECETTE"))
        self.btn_prod.pack(side="left", padx=4)
        self.btn_recette.pack(side="left", padx=4)
        self._update_env_buttons()

        # Status à droite
        self.status_var = tk.StringVar(value="Initialisation…")
        tk.Label(header, textvariable=self.status_var, font=("Consolas", 9),
                 fg=C["text3"], bg=C["bg2"]).pack(side="right", padx=20)

        # Spinner animé
        self.spinner_var = tk.StringVar(value="")
        tk.Label(header, textvariable=self.spinner_var, font=("Consolas", 14),
                 fg=C["cyan"], bg=C["bg2"]).pack(side="right", padx=4)

        # Séparateur bas header
        tk.Frame(self, bg=C["cyan"], height=2).pack(fill="x")

        # ══ BODY ═══════════════════════════════════════════════════════════════
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=0, pady=0)
        body.columnconfigure(0, weight=1, minsize=260)  # col users
        body.columnconfigure(1, weight=0)               # col catégories
        body.columnconfigure(2, weight=2)               # col streams
        body.columnconfigure(3, weight=1, minsize=220)  # col actions
        body.rowconfigure(0, weight=1)

        # ── Colonne 0 : Utilisateurs ──────────────────────────────────────────
        self._build_users_panel(body)

        # Séparateur
        tk.Frame(body, bg=C["border"], width=1).grid(row=0, column=1, sticky="ns", padx=0)

        # ── Colonne 2 : Catégories + Streams ──────────────────────────────────
        self._build_streams_panel(body)

        # Séparateur
        tk.Frame(body, bg=C["border"], width=1).grid(row=0, column=3, sticky="ns")

        # ── Colonne 4 : Actions + Logs ────────────────────────────────────────
        self._build_actions_panel(body)

    def _env_button(self, parent, label, icon, color, cmd) -> tk.Button:
        return tk.Button(
            parent, text=f"{icon} {label}",
            font=("Consolas", 10, "bold"),
            fg=C["text3"], bg=C["bg2"],
            activeforeground=color, activebackground=C["bg3"],
            relief="flat", bd=0, padx=10, pady=4,
            cursor="hand2", command=cmd,
        )

    # ── Panel Utilisateurs ────────────────────────────────────────────────────

    def _build_users_panel(self, parent) -> None:
        pnl = tk.Frame(parent, bg=C["bg"])
        pnl.grid(row=0, column=0, sticky="nsew")
        pnl.rowconfigure(2, weight=1)
        pnl.columnconfigure(0, weight=1)

        self._section_label(pnl, "UTILISATEURS", row=0)

        # Barre de recherche
        search_frame = tk.Frame(pnl, bg=C["bg2"], pady=8, padx=10)
        search_frame.grid(row=1, column=0, sticky="ew")
        search_frame.columnconfigure(1, weight=1)
        tk.Label(search_frame, text="⌕", font=("Consolas", 13),
                 fg=C["text3"], bg=C["bg2"]).grid(row=0, column=0, padx=(0,6))
        self.user_search_var = tk.StringVar()
        self.user_search_var.trace_add("write", self._filter_users)
        e = tk.Entry(search_frame, textvariable=self.user_search_var,
                     bg=C["bg3"], fg=C["text"], insertbackground=C["cyan"],
                     relief="flat", font=("Consolas", 10), bd=0)
        e.grid(row=0, column=1, sticky="ew", ipady=5)
        self._underline(search_frame, row=1, colspan=2)

        # Listbox
        lb_frame = tk.Frame(pnl, bg=C["bg"])
        lb_frame.grid(row=2, column=0, sticky="nsew")
        lb_frame.rowconfigure(0, weight=1)
        lb_frame.columnconfigure(0, weight=1)

        self.user_lb = tk.Listbox(
            lb_frame, selectmode=tk.MULTIPLE, bg=C["bg"],
            fg=C["text"], font=("Consolas", 10),
            selectbackground=C["select"], selectforeground=C["cyan"],
            activestyle="none", highlightthickness=0,
            relief="flat", bd=0, exportselection=False,
            cursor="hand2",
        )
        self.user_lb.grid(row=0, column=0, sticky="nsew")
        sb = tk.Scrollbar(lb_frame, bg=C["bg2"], troughcolor=C["bg2"],
                          command=self.user_lb.yview, relief="flat", bd=0, width=8)
        sb.grid(row=0, column=1, sticky="ns")
        self.user_lb.configure(yscrollcommand=sb.set)
        self.user_lb.bind("<<ListboxSelect>>", self._on_users_selected)

        # Compteur sélection
        self.user_sel_var = tk.StringVar(value="Aucun sélectionné")
        tk.Label(pnl, textvariable=self.user_sel_var, font=("Consolas", 8),
                 fg=C["text3"], bg=C["bg2"], anchor="w", padx=10, pady=4
        ).grid(row=3, column=0, sticky="ew")

    # ── Panel Streams ─────────────────────────────────────────────────────────

    def _build_streams_panel(self, parent) -> None:
        pnl = tk.Frame(parent, bg=C["bg"])
        pnl.grid(row=0, column=2, sticky="nsew")
        pnl.rowconfigure(2, weight=1)
        pnl.columnconfigure(0, weight=0, minsize=140)
        pnl.columnconfigure(1, weight=1)

        self._section_label(pnl, "STREAMS", row=0, colspan=2)

        # ── Sous-panneau catégories ───────────────────────────────────────────
        cat_pnl = tk.Frame(pnl, bg=C["bg2"])
        cat_pnl.grid(row=1, rowspan=2, column=0, sticky="nsew")
        cat_pnl.rowconfigure(1, weight=1)
        cat_pnl.columnconfigure(0, weight=1)

        tk.Label(cat_pnl, text="CATÉGORIES", font=("Consolas", 8, "bold"),
                 fg=C["text3"], bg=C["bg2"], pady=8).grid(row=0, column=0, sticky="ew")

        self.cat_lb = tk.Listbox(
            cat_pnl, selectmode=tk.MULTIPLE, bg=C["bg2"],
            fg=C["text2"], font=("Consolas", 10, "bold"),
            selectbackground=C["cyan_dark"], selectforeground=C["cyan"],
            activestyle="none", highlightthickness=0,
            relief="flat", bd=0, exportselection=False,
            cursor="hand2", width=14,
        )
        self.cat_lb.grid(row=1, column=0, sticky="nsew")
        self.cat_lb.bind("<<ListboxSelect>>", self._on_category_selected)

        sb_c = tk.Scrollbar(cat_pnl, bg=C["bg2"], troughcolor=C["bg2"],
                             command=self.cat_lb.yview, relief="flat", bd=0, width=6)
        sb_c.grid(row=1, column=1, sticky="ns")
        self.cat_lb.configure(yscrollcommand=sb_c.set)

        cat_btn = tk.Frame(cat_pnl, bg=C["bg2"], pady=6)
        cat_btn.grid(row=2, column=0, columnspan=2, sticky="ew")
        self._mini_btn(cat_btn, "✓ Tout", self._select_all_categories).pack(side="left", padx=4)
        self._mini_btn(cat_btn, "✗ Tout", self._deselect_all_categories).pack(side="left", padx=4)

        # ── Sous-panneau streams ──────────────────────────────────────────────
        stream_pnl = tk.Frame(pnl, bg=C["bg"])
        stream_pnl.grid(row=1, rowspan=2, column=1, sticky="nsew")
        stream_pnl.rowconfigure(1, weight=1)
        stream_pnl.columnconfigure(0, weight=1)

        # Barre recherche streams
        sf = tk.Frame(stream_pnl, bg=C["bg2"], pady=8, padx=10)
        sf.grid(row=0, column=0, columnspan=2, sticky="ew")
        sf.columnconfigure(1, weight=1)
        tk.Label(sf, text="⌕", font=("Consolas", 13),
                 fg=C["text3"], bg=C["bg2"]).grid(row=0, column=0, padx=(0,6))
        self.stream_search_var = tk.StringVar()
        self.stream_search_var.trace_add("write", self._filter_streams)
        tk.Entry(sf, textvariable=self.stream_search_var,
                 bg=C["bg3"], fg=C["text"], insertbackground=C["cyan"],
                 relief="flat", font=("Consolas", 10), bd=0
        ).grid(row=0, column=1, sticky="ew", ipady=5)
        self._underline(sf, row=1, colspan=2)

        lf = tk.Frame(stream_pnl, bg=C["bg"])
        lf.grid(row=1, column=0, sticky="nsew")
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        self.stream_lb = tk.Listbox(
            lf, selectmode=tk.MULTIPLE, bg=C["bg"],
            fg=C["text"], font=("Consolas", 10),
            selectbackground=C["select"], selectforeground=C["cyan"],
            activestyle="none", highlightthickness=0,
            relief="flat", bd=0, exportselection=False,
            cursor="hand2",
        )
        self.stream_lb.grid(row=0, column=0, sticky="nsew")
        sb_sy = tk.Scrollbar(lf, bg=C["bg2"], troughcolor=C["bg2"],
                              command=self.stream_lb.yview, relief="flat", bd=0, width=8)
        sb_sy.grid(row=0, column=1, sticky="ns")
        sb_sx = tk.Scrollbar(lf, bg=C["bg2"], troughcolor=C["bg2"],
                              orient="horizontal", command=self.stream_lb.xview, relief="flat", bd=0)
        sb_sx.grid(row=1, column=0, sticky="ew")
        self.stream_lb.configure(yscrollcommand=sb_sy.set, xscrollcommand=sb_sx.set)

        # Double-clic → détail stream
        self.stream_lb.bind("<Double-Button-1>", self._on_stream_double_click)
        DarkTooltip(self.stream_lb, "Double-clic pour voir les droits sur ce stream")

        # Boutons sélection rapide
        sel_frame = tk.Frame(stream_pnl, bg=C["bg2"], pady=6)
        sel_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=8)
        self._mini_btn(sel_frame, "✓ Tout",    self._select_all_streams).pack(side="left",  padx=4)
        self._mini_btn(sel_frame, "✗ Tout",    self._deselect_all_streams).pack(side="left", padx=4)
        self.stream_count_var = tk.StringVar(value="")
        tk.Label(sel_frame, textvariable=self.stream_count_var, font=("Consolas", 8),
                 fg=C["text3"], bg=C["bg2"]).pack(side="right", padx=8)
        self.stream_lb.bind("<<ListboxSelect>>", self._on_stream_select)

    # ── Panel Actions + Logs ──────────────────────────────────────────────────

    def _build_actions_panel(self, parent) -> None:
        pnl = tk.Frame(parent, bg=C["bg"])
        pnl.grid(row=0, column=4, sticky="nsew")
        pnl.rowconfigure(5, weight=1)
        pnl.columnconfigure(0, weight=1)

        self._section_label(pnl, "ACTIONS", row=0)

        # ── Permission picker ─────────────────────────────────────────────────
        perm_frame = tk.Frame(pnl, bg=C["bg2"], padx=14, pady=12)
        perm_frame.grid(row=1, column=0, sticky="ew", pady=(0,1))
        tk.Label(perm_frame, text="PERMISSION", font=("Consolas", 8, "bold"),
                 fg=C["text3"], bg=C["bg2"]).pack(anchor="w")

        self.perm_var = tk.StringVar(value="view")
        for perm in PERMISSIONS:
            color = perm_color(perm)
            icon  = perm_icon(perm)
            rb = tk.Radiobutton(
                perm_frame, text=f"  {icon}  {perm.upper()}",
                variable=self.perm_var, value=perm,
                fg=C["text2"], bg=C["bg2"],
                selectcolor=C["bg2"],
                activebackground=C["bg2"], activeforeground=color,
                font=("Consolas", 11, "bold"),
                cursor="hand2", relief="flat",
                command=lambda p=perm, c=color: self._on_perm_changed(p, c),
            )
            rb.pack(anchor="w", pady=2)

        self.perm_indicator = tk.Frame(perm_frame, bg=C["cyan"], height=2)
        self.perm_indicator.pack(fill="x", pady=(6,0))

        # ── Boutons d'action ──────────────────────────────────────────────────
        btn_frame = tk.Frame(pnl, bg=C["bg"], pady=8)
        btn_frame.grid(row=2, column=0, sticky="ew", padx=14)
        btn_frame.columnconfigure(0, weight=1)

        self.btn_inspect = self._action_btn(btn_frame, "🔍  INSPECTER",
                                            C["cyan"], self._show_permissions, row=0)
        self.btn_apply   = self._action_btn(btn_frame, "✅  APPLIQUER",
                                            C["green"], self._apply_permissions, row=1)
        self.btn_remove  = self._action_btn(btn_frame, "🗑   SUPPRIMER",
                                            C["red"], self._remove_permissions, row=2)

        tk.Frame(pnl, bg=C["border"], height=1).grid(row=3, column=0, sticky="ew", pady=8)

        self._mini_btn(pnl, "🔄  Rafraîchir les données",
                       self._load_data_async, full=True
        ).grid(row=4, column=0, sticky="ew", padx=14, pady=(0,8))

        # ── Logs ──────────────────────────────────────────────────────────────
        log_hdr = tk.Frame(pnl, bg=C["bg2"])
        log_hdr.grid(row=5, column=0, sticky="ew")

        tk.Label(log_hdr, text="JOURNAL", font=("Consolas", 8, "bold"),
                 fg=C["text3"], bg=C["bg2"], padx=14, pady=8).pack(side="left")
        self._mini_btn(log_hdr, "✗ Effacer", self._clear_logs
        ).pack(side="right", padx=8, pady=4)

        log_frame = tk.Frame(pnl, bg=C["bg"])
        log_frame.grid(row=6, column=0, sticky="nsew", padx=0)
        pnl.rowconfigure(6, weight=1)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_box = tk.Text(
            log_frame, state="disabled", wrap="word",
            bg=C["bg"], fg=C["text2"], font=("Consolas", 9),
            insertbackground=C["cyan"], relief="flat", bd=0,
            padx=12, pady=8, cursor="arrow",
        )
        self.log_box.grid(row=0, column=0, sticky="nsew")
        sb_log = tk.Scrollbar(log_frame, bg=C["bg2"], troughcolor=C["bg2"],
                               command=self.log_box.yview, relief="flat", bd=0, width=8)
        sb_log.grid(row=0, column=1, sticky="ns")
        self.log_box.configure(yscrollcommand=sb_log.set)
        self.log_box.tag_config("ok",    foreground=C["green"])
        self.log_box.tag_config("err",   foreground=C["red"])
        self.log_box.tag_config("info",  foreground=C["cyan"])
        self.log_box.tag_config("skip",  foreground=C["text3"])
        self.log_box.tag_config("head",  foreground=C["yellow"], font=("Consolas", 9, "bold"))
        self.log_box.tag_config("dim",   foreground=C["text3"])

    # ── Widgets helpers ───────────────────────────────────────────────────────

    def _section_label(self, parent, text: str, row: int, colspan: int = 1) -> None:
        f = tk.Frame(parent, bg=C["bg2"])
        f.grid(row=row, column=0, columnspan=colspan, sticky="ew")
        tk.Label(f, text=f"  {text}", font=("Consolas", 9, "bold"),
                 fg=C["text3"], bg=C["bg2"], pady=10, anchor="w"
        ).pack(fill="x")
        tk.Frame(f, bg=C["border"], height=1).pack(fill="x")

    def _underline(self, parent, row: int, colspan: int = 1) -> None:
        tk.Frame(parent, bg=C["border"], height=1).grid(
            row=row, column=0, columnspan=colspan, sticky="ew"
        )

    def _action_btn(self, parent, text: str, color: str, cmd, row: int) -> tk.Button:
        f = tk.Frame(parent, bg=C["bg"], pady=3)
        f.grid(row=row, column=0, sticky="ew")
        f.columnconfigure(0, weight=1)
        btn = tk.Button(
            f, text=text, font=("Consolas", 11, "bold"),
            fg=color, bg=C["bg3"],
            activeforeground=C["bg"], activebackground=color,
            relief="flat", bd=0, cursor="hand2",
            pady=10, command=cmd,
        )
        btn.grid(row=0, column=0, sticky="ew")
        # Hover effect
        btn.bind("<Enter>", lambda e, b=btn, c=color: b.configure(bg=c, fg=C["bg"]))
        btn.bind("<Leave>", lambda e, b=btn, c=color: b.configure(bg=C["bg3"], fg=c))
        return btn

    def _mini_btn(self, parent, text: str, cmd, full: bool = False) -> tk.Button:
        btn = tk.Button(
            parent, text=text, font=("Consolas", 9),
            fg=C["text2"], bg=C["bg3"],
            activeforeground=C["cyan"], activebackground=C["bg4"],
            relief="flat", bd=0, cursor="hand2",
            padx=8, pady=4, command=cmd,
        )
        if full:
            btn.configure(pady=8)
        btn.bind("<Enter>", lambda e: btn.configure(fg=C["cyan"]))
        btn.bind("<Leave>", lambda e: btn.configure(fg=C["text2"]))
        return btn

    # ── Environnement ─────────────────────────────────────────────────────────

    def _switch_env(self, env: str) -> None:
        if self.env.get() == env:
            return
        self.env.set(env)
        url = GRAYLOG_URL_PROD if env == "PROD" else GRAYLOG_URL_RECETTE
        self.client = GraylogClient(url)
        self._update_env_buttons()
        self.perms_cache.clear()
        self._log(f"\n⟳  Basculement vers {env}…", "head")
        self._load_data_async()

    def _update_env_buttons(self) -> None:
        env = self.env.get()
        self.btn_prod.configure(
            fg=C["prod"] if env == "PROD" else C["text3"],
            font=("Consolas", 10, "bold" if env == "PROD" else "normal"),
        )
        self.btn_recette.configure(
            fg=C["recette"] if env == "RECETTE" else C["text3"],
            font=("Consolas", 10, "bold" if env == "RECETTE" else "normal"),
        )

    # ── Chargement ────────────────────────────────────────────────────────────

    def _load_data_async(self) -> None:
        self._set_status("Chargement en cours…")
        self._start_spinner()
        self._log("Connexion à Graylog…", "info")
        threading.Thread(target=self._load_data, daemon=True).start()

    def _load_data(self) -> None:
        try:
            streams = self.client.get_streams()
            users   = self.client.get_users()
            self.after(0, self._populate, streams, users)
        except Exception as e:
            self.after(0, self._load_error, str(e))

    def _populate(self, streams: Dict[str,str], users: List[Dict[str,str]]) -> None:
        self._stop_spinner()
        self.streams = streams
        self.users   = users
        self.perms_cache.clear()
        self.sel_user_ids.clear()

        self._rebuild_users(users)
        self._rebuild_categories(streams)
        self._rebuild_streams(streams)

        env = self.env.get()
        color = C["prod"] if env == "PROD" else C["recette"]
        self._log(f"✓  {len(streams)} streams  ·  {len(users)} utilisateurs  [{env}]", "ok")
        self._set_status(f"[{env}]  {len(streams)} streams  ·  {len(users)} utilisateurs")

    def _load_error(self, msg: str) -> None:
        self._stop_spinner()
        self._log(f"✗  Erreur : {msg}", "err")
        self._set_status("Erreur de connexion")

    # ── Rebuild ───────────────────────────────────────────────────────────────

    def _rebuild_users(self, users: List[Dict[str,str]]) -> None:
        self.user_lb.delete(0, tk.END)
        self._user_id_map = {}
        for i, u in enumerate(sorted(users, key=lambda x: x["username"].lower())):
            self.user_lb.insert(tk.END, f"  {u['username']}")
            self._user_id_map[i] = u["id"]

    def _rebuild_categories(self, streams: Dict[str,str]) -> None:
        cats: Set[str] = set()
        for t in streams.values():
            c = extract_category(t)
            if c:
                cats.add(c)
        self.categories = sorted(cats, key=str.lower)
        self.cat_lb.delete(0, tk.END)
        for c in self.categories:
            self.cat_lb.insert(tk.END, f"  [{c}]")

    def _rebuild_streams(self, streams: Dict[str,str]) -> None:
        self.stream_lb.delete(0, tk.END)
        self.stream_id_map = {}
        for i, (sid, title) in enumerate(sorted(streams.items(), key=lambda x: x[1].lower())):
            self.stream_lb.insert(tk.END, f"  {title}")
            self.stream_id_map[i] = sid

    # ── Filtres ───────────────────────────────────────────────────────────────

    def _filter_users(self, *_) -> None:
        q = self.user_search_var.get().lower()
        filtered = [u for u in self.users if q in u["username"].lower() or q in u["full_name"].lower()]
        self._rebuild_users(filtered)

    def _filter_streams(self, *_) -> None:
        q = self.stream_search_var.get().lower()
        self._rebuild_streams({s:t for s,t in self.streams.items() if q in t.lower()})

    # ── Sélections ────────────────────────────────────────────────────────────

    def _on_category_selected(self, _=None) -> None:
        cats = {self.categories[i] for i in self.cat_lb.curselection()}
        if not cats:
            return
        self.stream_lb.selection_clear(0, tk.END)
        for i in range(self.stream_lb.size()):
            title = self.stream_lb.get(i).strip()
            if extract_category(title) in cats:
                self.stream_lb.selection_set(i)
        self._on_stream_select()
        self._log(f"  Catégorie(s) {sorted(cats)} → {len(self.stream_lb.curselection())} stream(s)", "info")

    def _select_all_categories(self) -> None:
        self.cat_lb.select_set(0, tk.END)
        self._on_category_selected()

    def _deselect_all_categories(self) -> None:
        self.cat_lb.selection_clear(0, tk.END)

    def _select_all_streams(self) -> None:
        self.stream_lb.select_set(0, tk.END)
        self._on_stream_select()

    def _deselect_all_streams(self) -> None:
        self.stream_lb.selection_clear(0, tk.END)
        self._on_stream_select()

    def _on_stream_select(self, _=None) -> None:
        n = len(self.stream_lb.curselection())
        self.stream_count_var.set(f"{n} sélectionné(s)" if n else "")

    def _on_users_selected(self, _=None) -> None:
        self.sel_user_ids = [self._user_id_map[i] for i in self.user_lb.curselection()]
        n = len(self.sel_user_ids)
        if n:
            names = [self.user_lb.get(i).strip() for i in self.user_lb.curselection()]
            self.user_sel_var.set(f"  {n} sélectionné(s) : {', '.join(names[:3])}{'…' if n>3 else ''}")
        else:
            self.user_sel_var.set("  Aucun sélectionné")
        for uid in self.sel_user_ids:
            if uid not in self.perms_cache:
                threading.Thread(target=self._cache_perms, args=(uid,), daemon=True).start()

    def _cache_perms(self, uid: str) -> None:
        self.perms_cache[uid] = self.client.get_user_permissions(uid)

    # ── Double-clic stream ────────────────────────────────────────────────────

    def _on_stream_double_click(self, event) -> None:
        idx = self.stream_lb.nearest(event.y)
        if idx < 0 or idx not in self.stream_id_map:
            return
        sid   = self.stream_id_map[idx]
        title = self.stream_lb.get(idx).strip()
        StreamDetailWindow(self, title, sid, self.client, self.users)

    # ── Permission changed ────────────────────────────────────────────────────

    def _on_perm_changed(self, perm: str, color: str) -> None:
        self.perm_indicator.configure(bg=color)

    # ── Guards ────────────────────────────────────────────────────────────────

    def _guard(self) -> bool:
        if not self.sel_user_ids:
            messagebox.showwarning("Attention", "Sélectionnez au moins un utilisateur.", parent=self)
            return False
        if not self.stream_lb.curselection():
            messagebox.showwarning("Attention", "Sélectionnez au moins un stream.", parent=self)
            return False
        return True

    def _get_selected_streams(self) -> List[Tuple[str,str]]:
        return [(self.stream_id_map[i], self.stream_lb.get(i).strip())
                for i in self.stream_lb.curselection()]

    def _username(self, uid: str) -> str:
        return next((u["username"] for u in self.users if u["id"] == uid), uid)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _show_permissions(self) -> None:
        if not self._guard():
            return
        self._log("\n── INSPECTION ─────────────────────", "head")
        for uid in self.sel_user_ids:
            perms = self.perms_cache.get(uid, {})
            self._log(f"  👤 {self._username(uid)}", "info")
            for sid, title in self._get_selected_streams():
                p = self.client.user_perm_on_stream(perms, sid)
                if p:
                    self._log(f"      {perm_icon(p)} {title}  →  {p}", "ok")
                else:
                    self._log(f"      ○ {title}  →  aucune permission", "skip")

    def _apply_permissions(self) -> None:
        if not self._guard():
            return
        cap  = self.perm_var.get()
        nu   = len(self.sel_user_ids)
        ns   = len(self.stream_lb.curselection())
        self._log(f"\n── APPLY  {perm_icon(cap)} {cap.upper()}  ·  {nu}u × {ns}s ─", "head")
        threading.Thread(target=self._run_apply, args=(cap,), daemon=True).start()

    def _run_apply(self, cap: str) -> None:
        ok = skip = err = 0
        streams = self._get_selected_streams()
        for uid in self.sel_user_ids:
            uname = self._username(uid)
            perms = self.perms_cache.get(uid, {})
            for sid, title in streams:
                if self.client.user_perm_on_stream(perms, sid) == cap:
                    self.after(0, self._log, f"  ⊘ [{uname}] {title}", "skip")
                    skip += 1
                    continue
                success, msg = self.client.set_permission(sid, uid, cap)
                if success:
                    self.after(0, self._log, f"  ✓ [{uname}] {title}", "ok")
                    ok += 1
                else:
                    self.after(0, self._log, f"  ✗ [{uname}] {title}  {msg}", "err")
                    err += 1
            if ok:
                self.perms_cache[uid] = self.client.get_user_permissions(uid)

        summary = f"\n  {ok} appliquées  ·  {skip} ignorées  ·  {err} erreurs"
        self.after(0, self._log, summary, "ok" if not err else "err")
        self.after(0, (messagebox.showinfo if not err else messagebox.showwarning),
                   "Résultat", summary.strip(), )

    def _remove_permissions(self) -> None:
        if not self._guard():
            return
        n = len(self.sel_user_ids) * len(self.stream_lb.curselection())
        if not messagebox.askyesno("Confirmer", f"Supprimer la permission pour {n} combinaison(s) ?", parent=self):
            return
        self._log("\n── SUPPRESSION ─────────────────────", "head")
        threading.Thread(target=self._run_remove, daemon=True).start()

    def _run_remove(self) -> None:
        ok = err = 0
        streams = self._get_selected_streams()
        for uid in self.sel_user_ids:
            uname = self._username(uid)
            for sid, title in streams:
                success, msg = self.client.remove_permission(sid, uid)
                if success:
                    self.after(0, self._log, f"  ✓ [{uname}] {title}", "ok")
                    ok += 1
                else:
                    self.after(0, self._log, f"  ✗ [{uname}] {title}  {msg}", "err")
                    err += 1
            if ok:
                self.perms_cache[uid] = self.client.get_user_permissions(uid)
        self.after(0, self._log, f"\n  {ok} supprimées  ·  {err} erreurs", "ok" if not err else "err")

    # ── Logs ──────────────────────────────────────────────────────────────────

    def _log(self, msg: str, tag: str = "dim") -> None:
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.log_box.see(tk.END)
        self.log_box.configure(state="disabled")

    def _clear_logs(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", tk.END)
        self.log_box.configure(state="disabled")

    # ── Status + Spinner ──────────────────────────────────────────────────────

    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)

    def _start_spinner(self) -> None:
        self._spinning = True
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        def _tick(i=0):
            if self._spinning:
                self.spinner_var.set(frames[i % len(frames)])
                self.after(80, _tick, i+1)
            else:
                self.spinner_var.set("")
        _tick()

    def _stop_spinner(self) -> None:
        self._spinning = False


# ─── Point d'entrée ───────────────────────────────────────────────────────────

def main() -> None:
    app = GraylogApp()
    app.mainloop()


if __name__ == "__main__":
    main()
