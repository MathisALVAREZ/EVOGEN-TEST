# -*- coding: utf-8 -*-
"""Graylog Permission Manager — Spirica Edition."""

import base64
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import tkinter as tk
from tkinter import ttk, messagebox
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
CATEGORY_RE                = re.compile(r"^\[([^\]#][^\]]*)\]")

# ─── Palette Spirica ──────────────────────────────────────────────────────────
C = {
    # Fonds
    "bg":           "#F5F7FA",   # gris très clair — fond principal
    "bg_white":     "#FFFFFF",   # blanc pur — cartes
    "bg_panel":     "#EEF1F6",   # fond panneaux latéraux
    "sidebar":      "#1B3A6B",   # bleu marine Spirica
    "sidebar_dark": "#122849",   # bleu marine foncé
    "sidebar_item": "#223F73",   # item sidebar hover

    # Accents
    "green":        "#00A878",   # vert Spirica signature
    "green_light":  "#E6F6F2",   # vert très clair
    "green_dark":   "#007A57",   # vert foncé
    "blue":         "#1B3A6B",   # bleu marine
    "blue_light":   "#E8EEF8",   # bleu très clair
    "blue_mid":     "#2D5AA0",   # bleu moyen liens/accents

    # Textes
    "text":         "#1A2340",   # bleu quasi-noir
    "text2":        "#4A5568",   # gris foncé
    "text3":        "#8896A8",   # gris moyen
    "text_light":   "#FFFFFF",   # blanc

    # États
    "view":         "#2D5AA0",   # bleu pour "view"
    "view_bg":      "#E8EEF8",
    "manage":       "#D97706",   # ambre pour "manage"
    "manage_bg":    "#FEF3C7",
    "own":          "#DC2626",   # rouge pour "own"
    "own_bg":       "#FEE2E2",

    # Env
    "prod":         "#00A878",   # vert PROD
    "prod_bg":      "#E6F6F2",
    "recette":      "#D97706",   # ambre RECETTE
    "recette_bg":   "#FEF3C7",

    # Misc
    "border":       "#D8E0EC",
    "border2":      "#C5D0E0",
    "shadow":       "#00000015",
    "hover":        "#F0F4FF",
    "select":       "#D4E3FF",
    "red":          "#DC2626",
    "success":      "#00A878",
    "warning":      "#D97706",
    "error":        "#DC2626",
}

FONT_TITLE  = ("Segoe UI", 13, "bold")
FONT_LABEL  = ("Segoe UI", 10)
FONT_BOLD   = ("Segoe UI", 10, "bold")
FONT_SMALL  = ("Segoe UI", 9)
FONT_MONO   = ("Consolas", 9)
FONT_HEADER = ("Segoe UI", 11, "bold")
FONT_BIG    = ("Segoe UI", 14, "bold")


# ─── Client API ───────────────────────────────────────────────────────────────

class GraylogClient:
    def __init__(self, url: str) -> None:
        self.base_url = url.rstrip("/")
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers.update(self._headers())

    def _headers(self) -> Dict[str, str]:
        b64 = base64.b64encode(f"{GRAYLOG_USERNAME}:{GRAYLOG_PASSWORD}".encode()).decode()
        return {"Authorization": f"Basic {b64}", "Accept": "application/json",
                "Content-Type": "application/json", "X-Requested-By": "graylog-manager"}

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
        return [{"id": u["id"], "username": u.get("username",""), "full_name": u.get("full_name","")}
                for u in (d or {}).get("users", [])]

    def get_user_permissions(self, uid: str) -> Dict[str, Any]:
        return self._req("get", f"/api/authz/shares/user/{uid}") or {}

    def user_perm_on_stream(self, perms: Dict, sid: str) -> Optional[str]:
        return perms.get("context",{}).get("grantee_capabilities",{}).get(f"{GRN_PREFIX}{sid}")

    def get_stream_grantees(self, stream_id: str) -> Dict[str, str]:
        grn = f"{GRN_PREFIX}{stream_id}"
        enc = quote(grn, safe="")
        url = f"{self.base_url}/api/authz/shares/entities/{enc}/prepare"
        try:
            r = self.session.post(url, json={}, timeout=15)
            if r.status_code in (200, 201):
                d = r.json()
                return d.get("selected_grantee_capabilities") or d.get("grantees") or {}
        except Exception as e:
            logger.error("get_stream_grantees: %s", e)
        return {}

    def _prepare(self, grn: str) -> Optional[Dict]:
        enc = quote(grn, safe="")
        url = f"{self.base_url}/api/authz/shares/entities/{enc}/prepare"
        try:
            r = self.session.post(url, json={}, timeout=15)
            return r.json() if r.status_code in (200, 201) else None
        except Exception as e:
            logger.error("prepare: %s", e)
            return None

    def _post_shares(self, grn: str, grantees: Dict[str, str]) -> Tuple[bool, str]:
        enc = quote(grn, safe="")
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
        if p is None: return False, "prepare failed"
        ex   = dict(p.get("selected_grantee_capabilities") or p.get("grantees") or {})
        ex[ugrn] = cap
        ok, msg = self._post_shares(grn, ex)
        return (True, f"OK") if ok else (False, msg)

    def remove_permission(self, sid: str, uid: str) -> Tuple[bool, str]:
        grn  = f"{GRN_PREFIX}{sid}"
        ugrn = f"{GRN_USER_PREFIX}{uid}"
        p    = self._prepare(grn)
        if p is None: return False, "prepare failed"
        ex   = {k:v for k,v in (p.get("selected_grantee_capabilities") or p.get("grantees") or {}).items() if k != ugrn}
        ok, msg = self._post_shares(grn, ex)
        return (True, "Supprimé") if ok else (False, msg)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def extract_category(title: str) -> Optional[str]:
    m = CATEGORY_RE.match(title.strip())
    return m.group(1).strip() if m else None

def perm_color(p: str) -> str:
    return {"view": C["view"], "manage": C["manage"], "own": C["own"]}.get(p, C["text3"])

def perm_bg(p: str) -> str:
    return {"view": C["view_bg"], "manage": C["manage_bg"], "own": C["own_bg"]}.get(p, C["bg"])

def perm_icon(p: str) -> str:
    return {"view": "👁", "manage": "⚙", "own": "👑"}.get(p, "•")


# ─── Tooltip ──────────────────────────────────────────────────────────────────

class Tooltip:
    def __init__(self, w: tk.Widget, text: str) -> None:
        self.w = w; self.text = text; self.tw = None
        w.bind("<Enter>", self._show); w.bind("<Leave>", self._hide)

    def _show(self, _=None):
        x = self.w.winfo_rootx() + 16
        y = self.w.winfo_rooty() + self.w.winfo_height() + 4
        self.tw = tk.Toplevel(self.w)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tw, text=self.text, bg=C["text"], fg=C["text_light"],
                 font=FONT_SMALL, padx=10, pady=5, relief="flat").pack()

    def _hide(self, _=None):
        if self.tw: self.tw.destroy(); self.tw = None


# ─── Popup : droits d'un stream ───────────────────────────────────────────────

class StreamDetailWindow(tk.Toplevel):
    def __init__(self, parent, title: str, sid: str,
                 client: GraylogClient, users: List[Dict]) -> None:
        super().__init__(parent)
        self.title(f"Droits — {title}")
        self.configure(bg=C["bg"])
        self.geometry("580x500")
        self.resizable(True, True)
        self.grab_set()

        self._grn_to_user: Dict[str,Dict] = {
            f"{GRN_USER_PREFIX}{u['id']}": u for u in users
        }
        self._build(title, sid, client)

    def _build(self, title: str, sid: str, client: GraylogClient) -> None:
        # Header
        hdr = tk.Frame(self, bg=C["sidebar"], pady=20, padx=24)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Droits sur le stream", font=FONT_SMALL,
                 fg="#AABBDD", bg=C["sidebar"]).pack(anchor="w")
        tk.Label(hdr, text=title, font=FONT_BIG,
                 fg=C["text_light"], bg=C["sidebar"]).pack(anchor="w", pady=(2,0))

        # Accent bar
        tk.Frame(self, bg=C["green"], height=3).pack(fill="x")

        # Content
        content = tk.Frame(self, bg=C["bg"], padx=20, pady=16)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(1, weight=1)

        # En-têtes colonnes
        hrow = tk.Frame(content, bg=C["bg_panel"])
        hrow.pack(fill="x", pady=(0, 6))
        tk.Label(hrow, text="Utilisateur", font=FONT_BOLD, fg=C["text3"],
                 bg=C["bg_panel"], anchor="w", padx=14, pady=8, width=28).pack(side="left")
        tk.Label(hrow, text="Nom complet", font=FONT_BOLD, fg=C["text3"],
                 bg=C["bg_panel"], anchor="w", padx=8, pady=8, width=22).pack(side="left")
        tk.Label(hrow, text="Permission", font=FONT_BOLD, fg=C["text3"],
                 bg=C["bg_panel"], anchor="w", padx=8, pady=8, width=12).pack(side="left")

        # Zone scroll
        scroll_frame = tk.Frame(content, bg=C["bg"])
        scroll_frame.pack(fill="both", expand=True)
        scroll_frame.columnconfigure(0, weight=1)
        scroll_frame.rowconfigure(0, weight=1)

        canvas = tk.Canvas(scroll_frame, bg=C["bg"], highlightthickness=0)
        sb     = ttk.Scrollbar(scroll_frame, orient="vertical", command=canvas.yview)
        self.inner = tk.Frame(canvas, bg=C["bg"])
        self.inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Indicateur de chargement
        self.loading = tk.Label(self.inner, text="Chargement…", font=FONT_LABEL,
                                fg=C["text3"], bg=C["bg"], pady=30)
        self.loading.pack()

        threading.Thread(target=self._load, args=(sid, client), daemon=True).start()

    def _load(self, sid: str, client: GraylogClient) -> None:
        g = client.get_stream_grantees(sid)
        self.after(0, self._populate, g)

    def _populate(self, grantees: Dict[str, str]) -> None:
        self.loading.destroy()
        if not grantees:
            tk.Label(self.inner, text="Aucun droit explicite configuré.",
                     font=FONT_LABEL, fg=C["text3"], bg=C["bg"], pady=40).pack()
            return

        order = {"own":0, "manage":1, "view":2}
        items = sorted(grantees.items(), key=lambda x: (order.get(x[1],9), x[0]))

        for i, (grn, cap) in enumerate(items):
            u    = self._grn_to_user.get(grn, {})
            name = u.get("username", grn.split(":")[-1])
            full = u.get("full_name", "—")
            bg   = C["bg_white"] if i % 2 == 0 else C["bg"]

            row = tk.Frame(self.inner, bg=bg, pady=2)
            row.pack(fill="x")

            tk.Label(row, text=name, font=FONT_BOLD, fg=C["text"],
                     bg=bg, anchor="w", padx=14, width=28).pack(side="left")
            tk.Label(row, text=full, font=FONT_LABEL, fg=C["text2"],
                     bg=bg, anchor="w", padx=8, width=22).pack(side="left")

            badge_frame = tk.Frame(row, bg=bg, padx=8)
            badge_frame.pack(side="left")
            badge = tk.Label(badge_frame, text=f"  {perm_icon(cap)} {cap}  ",
                             font=("Segoe UI", 9, "bold"),
                             fg=perm_color(cap), bg=perm_bg(cap),
                             padx=4, pady=3, relief="flat")
            badge.pack(anchor="w", pady=4)

        # Footer
        tk.Frame(self.inner, bg=C["border"], height=1).pack(fill="x", pady=8, padx=8)
        tk.Label(self.inner, text=f"{len(grantees)} entrée(s) au total",
                 font=FONT_SMALL, fg=C["text3"], bg=C["bg"]).pack(anchor="e", padx=14, pady=4)


# ─── Application principale ───────────────────────────────────────────────────

class GraylogApp(tk.Tk):

    def __init__(self) -> None:
        super().__init__()
        self.title("Graylog Permission Manager · Spirica")
        self.geometry("1350x860")
        self.minsize(1100, 680)
        self.configure(bg=C["bg"])

        self.env            = "PROD"
        self.client         = GraylogClient(GRAYLOG_URL_PROD)
        self.streams:       Dict[str,str]      = {}
        self.stream_id_map: Dict[int,str]      = {}
        self.users:         List[Dict[str,str]] = []
        self._user_id_map:  Dict[int,str]      = {}
        self.categories:    List[str]          = []
        self.sel_user_ids:  List[str]          = []
        self.perms_cache:   Dict[str,Dict]     = {}
        self._spinning      = False

        self._style()
        self._build()
        self._load_async()

    # ── Style ttk ─────────────────────────────────────────────────────────────

    def _style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["text"],
                    font=FONT_LABEL, bordercolor=C["border"],
                    troughcolor=C["bg_panel"], selectbackground=C["select"],
                    selectforeground=C["text"])
        s.configure("TScrollbar", background=C["border"], troughcolor=C["bg_panel"],
                    arrowcolor=C["text3"], bordercolor=C["border"], relief="flat", width=8)
        s.map("TScrollbar", background=[("active", C["border2"])])
        s.configure("TEntry", fieldbackground=C["bg_white"], foreground=C["text"],
                    insertcolor=C["blue"], bordercolor=C["border"],
                    lightcolor=C["bg_white"], darkcolor=C["bg_white"], relief="flat", padding=8)
        s.map("TEntry", bordercolor=[("focus", C["blue_mid"])])
        s.configure("Vertical.TScrollbar", width=8)

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.columnconfigure(0, weight=0)  # sidebar
        self.columnconfigure(1, weight=1)  # main
        self.rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()

    # ── SIDEBAR ───────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        sb = tk.Frame(self, bg=C["sidebar"], width=240)
        sb.grid(row=0, column=0, sticky="ns")
        sb.pack_propagate(False)
        sb.columnconfigure(0, weight=1)

        # Logo
        logo = tk.Frame(sb, bg=C["sidebar"], pady=24, padx=20)
        logo.pack(fill="x")
        tk.Label(logo, text="SPIRICA", font=("Segoe UI", 18, "bold"),
                 fg=C["text_light"], bg=C["sidebar"]).pack(anchor="w")
        tk.Label(logo, text="Permission Manager", font=("Segoe UI", 9),
                 fg="#8BAAD4", bg=C["sidebar"]).pack(anchor="w")

        # Séparateur vert
        tk.Frame(sb, bg=C["green"], height=2).pack(fill="x")

        # ENV switcher
        env_section = tk.Frame(sb, bg=C["sidebar"], pady=16, padx=16)
        env_section.pack(fill="x")
        tk.Label(env_section, text="ENVIRONNEMENT", font=("Segoe UI", 8, "bold"),
                 fg="#6688AA", bg=C["sidebar"]).pack(anchor="w", pady=(0,8))

        self.btn_prod = self._env_btn(env_section, "PROD", C["prod"], C["prod_bg"], "PROD")
        self.btn_prod.pack(fill="x", pady=2)
        self.btn_rec  = self._env_btn(env_section, "RECETTE", C["recette"], C["recette_bg"], "RECETTE")
        self.btn_rec.pack(fill="x", pady=2)
        self._refresh_env_btns()

        tk.Frame(sb, bg="#243F6A", height=1).pack(fill="x", padx=16)

        # Section permissions
        perm_section = tk.Frame(sb, bg=C["sidebar"], pady=16, padx=16)
        perm_section.pack(fill="x")
        tk.Label(perm_section, text="PERMISSION", font=("Segoe UI", 8, "bold"),
                 fg="#6688AA", bg=C["sidebar"]).pack(anchor="w", pady=(0,8))

        self.perm_var = tk.StringVar(value="view")
        for perm in PERMISSIONS:
            self._perm_radio(perm_section, perm)

        # Séparateur
        tk.Frame(sb, bg="#243F6A", height=1).pack(fill="x", padx=16)

        # Boutons action
        action_section = tk.Frame(sb, bg=C["sidebar"], pady=16, padx=16)
        action_section.pack(fill="x")
        tk.Label(action_section, text="ACTIONS", font=("Segoe UI", 8, "bold"),
                 fg="#6688AA", bg=C["sidebar"]).pack(anchor="w", pady=(0,8))

        self._sb_action_btn(action_section, "🔍  Inspecter",  C["blue_mid"],   self._show_permissions).pack(fill="x", pady=2)
        self._sb_action_btn(action_section, "✅  Appliquer",  C["green"],      self._apply_permissions).pack(fill="x", pady=2)
        self._sb_action_btn(action_section, "🗑  Supprimer",  C["own"],        self._remove_permissions).pack(fill="x", pady=2)

        tk.Frame(sb, bg="#243F6A", height=1).pack(fill="x", padx=16)

        refresh_frame = tk.Frame(sb, bg=C["sidebar"], padx=16, pady=10)
        refresh_frame.pack(fill="x")
        self._sb_ghost_btn(refresh_frame, "↺  Rafraîchir les données", self._load_async).pack(fill="x")

        # Statut en bas
        sb.pack_propagate(False)
        status_frame = tk.Frame(sb, bg=C["sidebar_dark"], pady=12, padx=16)
        status_frame.pack(side="bottom", fill="x")

        self.spinner_var = tk.StringVar(value="")
        spin_lbl = tk.Label(status_frame, textvariable=self.spinner_var,
                            font=("Segoe UI", 11), fg=C["green"], bg=C["sidebar_dark"])
        spin_lbl.pack(side="left")

        self.status_var = tk.StringVar(value="Démarrage…")
        tk.Label(status_frame, textvariable=self.status_var, font=("Segoe UI", 8),
                 fg="#8BAAD4", bg=C["sidebar_dark"], wraplength=180, justify="left").pack(side="left", padx=6)

    def _env_btn(self, parent, label: str, color: str, bg_color: str, env: str) -> tk.Button:
        btn = tk.Button(parent, text=f"  ● {label}  ",
                        font=("Segoe UI", 10, "bold"),
                        fg=C["text3"], bg=C["sidebar_item"],
                        activeforeground=color, activebackground=C["sidebar_item"],
                        relief="flat", bd=0, cursor="hand2",
                        anchor="w", padx=10, pady=8,
                        command=lambda: self._switch_env(env))
        btn.bind("<Enter>", lambda e: btn.configure(fg=color))
        btn.bind("<Leave>", lambda _: self._refresh_env_btns())
        return btn

    def _perm_radio(self, parent, perm: str) -> None:
        color = perm_color(perm)
        icon  = perm_icon(perm)
        f = tk.Frame(parent, bg=C["sidebar"], cursor="hand2")
        f.pack(fill="x", pady=1)

        indicator = tk.Frame(f, bg=C["sidebar"], width=3)
        indicator.pack(side="left", fill="y")

        rb = tk.Radiobutton(f,
            text=f"  {icon}  {perm.capitalize()}",
            variable=self.perm_var, value=perm,
            font=("Segoe UI", 10), fg="#AABBDD",
            bg=C["sidebar"], activebackground=C["sidebar_item"],
            activeforeground=color, selectcolor=C["sidebar"],
            relief="flat", cursor="hand2",
            command=lambda i=indicator, c=color: self._on_perm_select(i, c),
        )
        rb.pack(side="left", fill="x", expand=True, padx=4, pady=4)

        # Mettre à jour indicator si sélectionné par défaut
        if perm == self.perm_var.get():
            indicator.configure(bg=color)

    def _on_perm_select(self, indicator: tk.Frame, color: str) -> None:
        # Reset all indicators
        for w in indicator.master.master.winfo_children():
            try:
                w.winfo_children()[0].configure(bg=C["sidebar"])
            except:
                pass
        indicator.configure(bg=color)

    def _sb_action_btn(self, parent, text: str, color: str, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, font=("Segoe UI", 10, "bold"),
                        fg=color, bg=C["sidebar_item"],
                        activeforeground=C["text_light"], activebackground=color,
                        relief="flat", bd=0, cursor="hand2",
                        anchor="w", padx=12, pady=9, command=cmd)
        btn.bind("<Enter>", lambda e: btn.configure(bg=color, fg=C["text_light"]))
        btn.bind("<Leave>", lambda e: btn.configure(bg=C["sidebar_item"], fg=color))
        return btn

    def _sb_ghost_btn(self, parent, text: str, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, font=("Segoe UI", 9),
                        fg="#6688AA", bg=C["sidebar"],
                        activeforeground=C["text_light"], activebackground=C["sidebar_item"],
                        relief="flat", bd=0, cursor="hand2",
                        anchor="w", padx=4, pady=6, command=cmd)
        btn.bind("<Enter>", lambda e: btn.configure(fg=C["text_light"]))
        btn.bind("<Leave>", lambda e: btn.configure(fg="#6688AA"))
        return btn

    def _refresh_env_btns(self) -> None:
        prod_active    = self.env == "PROD"
        rec_active     = self.env == "RECETTE"
        self.btn_prod.configure(fg=C["prod"]    if prod_active else C["text3"],
                                bg=C["sidebar_dark"] if prod_active else C["sidebar_item"])
        self.btn_rec.configure( fg=C["recette"] if rec_active  else C["text3"],
                                bg=C["sidebar_dark"] if rec_active  else C["sidebar_item"])

    # ── MAIN ─────────────────────────────────────────────────────────────────

    def _build_main(self) -> None:
        main = tk.Frame(self, bg=C["bg"])
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1, minsize=280)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=1)

        # Colonne gauche : utilisateurs
        self._build_users_col(main)

        # Séparateur
        tk.Frame(main, bg=C["border"], width=1).grid(row=0, column=1, sticky="ns")

        # Colonne droite : catégories + streams + logs
        self._build_right_col(main)

    # ── Colonne Utilisateurs ──────────────────────────────────────────────────

    def _build_users_col(self, parent) -> None:
        col = tk.Frame(parent, bg=C["bg"])
        col.grid(row=0, column=0, sticky="nsew")
        col.rowconfigure(2, weight=1)
        col.columnconfigure(0, weight=1)

        # En-tête de section
        self._section_header(col, "Utilisateurs", "Ctrl+clic pour multi-sélection", row=0)

        # Barre de recherche
        search = tk.Frame(col, bg=C["bg_white"], padx=14, pady=10)
        search.grid(row=1, column=0, sticky="ew")
        search.columnconfigure(1, weight=1)
        tk.Label(search, text="🔍", font=("Segoe UI", 11),
                 fg=C["text3"], bg=C["bg_white"]).grid(row=0, column=0, padx=(0,8))
        self.user_search_var = tk.StringVar()
        self.user_search_var.trace_add("write", self._filter_users)
        e = tk.Entry(search, textvariable=self.user_search_var,
                     font=FONT_LABEL, bg=C["bg_white"], fg=C["text"],
                     relief="flat", bd=0, insertbackground=C["blue"])
        e.grid(row=0, column=1, sticky="ew", ipady=2)
        tk.Frame(search, bg=C["border"], height=1).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6,0))

        # Liste
        lb_wrap = tk.Frame(col, bg=C["bg_white"])
        lb_wrap.grid(row=2, column=0, sticky="nsew", padx=0, pady=0)
        lb_wrap.rowconfigure(0, weight=1)
        lb_wrap.columnconfigure(0, weight=1)

        self.user_lb = tk.Listbox(
            lb_wrap, selectmode=tk.MULTIPLE, bg=C["bg_white"],
            fg=C["text"], font=FONT_LABEL,
            selectbackground=C["blue_light"], selectforeground=C["blue"],
            activestyle="none", highlightthickness=0,
            relief="flat", bd=0, exportselection=False,
            cursor="hand2",
        )
        self.user_lb.grid(row=0, column=0, sticky="nsew")
        sb_u = ttk.Scrollbar(lb_wrap, command=self.user_lb.yview)
        sb_u.grid(row=0, column=1, sticky="ns")
        self.user_lb.configure(yscrollcommand=sb_u.set)
        self.user_lb.bind("<<ListboxSelect>>", self._on_users_sel)

        # Footer sélection
        self.user_sel_var = tk.StringVar(value="Aucun utilisateur sélectionné")
        footer = tk.Frame(col, bg=C["bg_panel"], padx=14, pady=6)
        footer.grid(row=3, column=0, sticky="ew")
        tk.Label(footer, textvariable=self.user_sel_var, font=FONT_SMALL,
                 fg=C["text3"], bg=C["bg_panel"], anchor="w").pack(fill="x")

    # ── Colonne Droite ────────────────────────────────────────────────────────

    def _build_right_col(self, parent) -> None:
        col = tk.Frame(parent, bg=C["bg"])
        col.grid(row=0, column=2, sticky="nsew")
        col.rowconfigure(1, weight=3)
        col.rowconfigure(3, weight=1)
        col.columnconfigure(0, weight=1)

        self._section_header(col, "Streams", "Double-clic = voir les droits", row=0)

        # Zone streams (catégories + liste)
        streams_area = tk.Frame(col, bg=C["bg"])
        streams_area.grid(row=1, column=0, sticky="nsew")
        streams_area.rowconfigure(1, weight=1)
        streams_area.columnconfigure(0, weight=0)
        streams_area.columnconfigure(1, weight=1)

        # Panel catégories
        self._build_categories_panel(streams_area)

        # Séparateur vertical
        tk.Frame(streams_area, bg=C["border"], width=1).grid(row=0, column=1, rowspan=3, sticky="ns")

        # Panel streams
        self._build_streams_panel(streams_area)

        # Séparateur horizontal
        tk.Frame(col, bg=C["border"], height=1).grid(row=2, column=0, sticky="ew")

        # Journal
        self._build_log_panel(col, row=3)

    def _build_categories_panel(self, parent) -> None:
        panel = tk.Frame(parent, bg=C["bg_white"], width=170)
        panel.grid(row=0, column=0, rowspan=3, sticky="nsew")
        panel.pack_propagate(False)
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)

        tk.Label(panel, text="CATÉGORIES", font=("Segoe UI", 8, "bold"),
                 fg=C["text3"], bg=C["bg_panel"], anchor="w",
                 padx=14, pady=10).pack(fill="x")
        tk.Frame(panel, bg=C["border"], height=1).pack(fill="x")

        lb_f = tk.Frame(panel, bg=C["bg_white"])
        lb_f.pack(fill="both", expand=True)
        lb_f.rowconfigure(0, weight=1)
        lb_f.columnconfigure(0, weight=1)

        self.cat_lb = tk.Listbox(
            lb_f, selectmode=tk.MULTIPLE, bg=C["bg_white"],
            fg=C["text"], font=FONT_BOLD,
            selectbackground=C["green_light"], selectforeground=C["green_dark"],
            activestyle="none", highlightthickness=0,
            relief="flat", bd=0, exportselection=False,
            cursor="hand2",
        )
        self.cat_lb.grid(row=0, column=0, sticky="nsew")
        sb_c = ttk.Scrollbar(lb_f, command=self.cat_lb.yview)
        sb_c.grid(row=0, column=1, sticky="ns")
        self.cat_lb.configure(yscrollcommand=sb_c.set)
        self.cat_lb.bind("<<ListboxSelect>>", self._on_cat_sel)

        tk.Frame(panel, bg=C["border"], height=1).pack(fill="x")
        cat_btns = tk.Frame(panel, bg=C["bg_panel"], pady=6)
        cat_btns.pack(fill="x")
        self._small_link_btn(cat_btns, "Tout ✓", self._sel_all_cats).pack(side="left", padx=8)
        self._small_link_btn(cat_btns, "Tout ✗", self._desel_cats).pack(side="left")

    def _build_streams_panel(self, parent) -> None:
        panel = tk.Frame(parent, bg=C["bg_white"])
        panel.grid(row=0, column=2, sticky="nsew")
        panel.rowconfigure(1, weight=1)
        panel.columnconfigure(0, weight=1)

        # Barre recherche
        sf = tk.Frame(panel, bg=C["bg_white"], padx=14, pady=10)
        sf.grid(row=0, column=0, columnspan=2, sticky="ew")
        sf.columnconfigure(1, weight=1)
        tk.Label(sf, text="🔍", font=("Segoe UI", 11),
                 fg=C["text3"], bg=C["bg_white"]).grid(row=0, column=0, padx=(0,8))
        self.stream_search_var = tk.StringVar()
        self.stream_search_var.trace_add("write", self._filter_streams)
        tk.Entry(sf, textvariable=self.stream_search_var,
                 font=FONT_LABEL, bg=C["bg_white"], fg=C["text"],
                 relief="flat", bd=0, insertbackground=C["blue"]
        ).grid(row=0, column=1, sticky="ew", ipady=2)
        tk.Frame(sf, bg=C["border"], height=1).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6,0))

        # Liste
        lf = tk.Frame(panel, bg=C["bg_white"])
        lf.grid(row=1, column=0, sticky="nsew")
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        self.stream_lb = tk.Listbox(
            lf, selectmode=tk.MULTIPLE, bg=C["bg_white"],
            fg=C["text"], font=FONT_LABEL,
            selectbackground=C["blue_light"], selectforeground=C["blue"],
            activestyle="none", highlightthickness=0,
            relief="flat", bd=0, exportselection=False,
            cursor="hand2",
        )
        self.stream_lb.grid(row=0, column=0, sticky="nsew")
        sb_sy = ttk.Scrollbar(lf, command=self.stream_lb.yview)
        sb_sy.grid(row=0, column=1, sticky="ns")
        self.stream_lb.configure(yscrollcommand=sb_sy.set)
        self.stream_lb.bind("<Double-Button-1>", self._on_stream_dbl)
        self.stream_lb.bind("<<ListboxSelect>>", self._on_stream_sel)
        Tooltip(self.stream_lb, "Double-clic pour voir les droits sur ce stream")

        # Footer
        tk.Frame(panel, bg=C["border"], height=1).grid(row=2, column=0, columnspan=2, sticky="ew")
        footer = tk.Frame(panel, bg=C["bg_panel"], pady=6, padx=12)
        footer.grid(row=3, column=0, columnspan=2, sticky="ew")
        self._small_link_btn(footer, "Tout sélectionner",    self._sel_all_streams).pack(side="left")
        tk.Label(footer, text=" · ", fg=C["text3"], bg=C["bg_panel"], font=FONT_SMALL).pack(side="left")
        self._small_link_btn(footer, "Tout désélectionner",  self._desel_streams).pack(side="left")
        self.stream_count_lbl = tk.Label(footer, text="", font=FONT_SMALL,
                                         fg=C["green_dark"], bg=C["bg_panel"])
        self.stream_count_lbl.pack(side="right")

    def _build_log_panel(self, parent, row: int) -> None:
        panel = tk.Frame(parent, bg=C["bg_white"])
        panel.grid(row=row, column=0, sticky="nsew")
        panel.rowconfigure(1, weight=1)
        panel.columnconfigure(0, weight=1)

        # Header log
        log_hdr = tk.Frame(panel, bg=C["bg_panel"])
        log_hdr.grid(row=0, column=0, sticky="ew")
        tk.Label(log_hdr, text="Journal d'activité", font=FONT_BOLD,
                 fg=C["text2"], bg=C["bg_panel"], padx=14, pady=8).pack(side="left")
        self._small_link_btn(log_hdr, "Effacer", self._clear_log).pack(side="right", padx=12)

        # Zone texte
        lf = tk.Frame(panel, bg=C["bg_white"])
        lf.grid(row=1, column=0, sticky="nsew")
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        self.log_box = tk.Text(lf, state="disabled", wrap="word",
                               bg=C["bg_white"], fg=C["text2"], font=FONT_MONO,
                               relief="flat", bd=0, padx=14, pady=8, cursor="arrow")
        self.log_box.grid(row=0, column=0, sticky="nsew")
        sb_log = ttk.Scrollbar(lf, command=self.log_box.yview)
        sb_log.grid(row=0, column=1, sticky="ns")
        self.log_box.configure(yscrollcommand=sb_log.set)

        # Tags log
        self.log_box.tag_config("ok",   foreground=C["success"],  font=("Consolas", 9, "bold"))
        self.log_box.tag_config("err",  foreground=C["error"],    font=("Consolas", 9, "bold"))
        self.log_box.tag_config("warn", foreground=C["warning"],  font=("Consolas", 9, "bold"))
        self.log_box.tag_config("info", foreground=C["blue_mid"], font=("Consolas", 9))
        self.log_box.tag_config("skip", foreground=C["text3"],    font=("Consolas", 9))
        self.log_box.tag_config("head", foreground=C["blue"],     font=("Consolas", 9, "bold"))
        self.log_box.tag_config("ts",   foreground=C["text3"],    font=("Consolas", 9))

    # ── Widgets helpers ───────────────────────────────────────────────────────

    def _section_header(self, parent, title: str, subtitle: str = "", row: int = 0) -> None:
        f = tk.Frame(parent, bg=C["bg_white"])
        f.grid(row=row, column=0, columnspan=10, sticky="ew")
        inner = tk.Frame(f, bg=C["bg_white"], padx=16, pady=14)
        inner.pack(fill="x")
        tk.Label(inner, text=title, font=FONT_HEADER, fg=C["text"], bg=C["bg_white"]).pack(side="left")
        if subtitle:
            tk.Label(inner, text=f"  —  {subtitle}", font=FONT_SMALL,
                     fg=C["text3"], bg=C["bg_white"]).pack(side="left")
        tk.Frame(f, bg=C["border"], height=1).pack(fill="x")

    def _small_link_btn(self, parent, text: str, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, font=FONT_SMALL,
                        fg=C["blue_mid"], bg=parent.cget("bg"),
                        activeforeground=C["green_dark"], activebackground=parent.cget("bg"),
                        relief="flat", bd=0, cursor="hand2", command=cmd)
        btn.bind("<Enter>", lambda e: btn.configure(fg=C["green_dark"]))
        btn.bind("<Leave>", lambda e: btn.configure(fg=C["blue_mid"]))
        return btn

    # ── Environnement ─────────────────────────────────────────────────────────

    def _switch_env(self, env: str) -> None:
        if self.env == env: return
        self.env    = env
        self.client = GraylogClient(GRAYLOG_URL_PROD if env == "PROD" else GRAYLOG_URL_RECETTE)
        self.perms_cache.clear()
        self._refresh_env_btns()
        self._log(f"Basculement vers {env}", "info")
        self._load_async()

    # ── Chargement ────────────────────────────────────────────────────────────

    def _load_async(self) -> None:
        self._set_status("Chargement…")
        self._start_spinner()
        self._log(f"Connexion à Graylog [{self.env}]…", "info")
        threading.Thread(target=self._load, daemon=True).start()

    def _load(self) -> None:
        try:
            streams = self.client.get_streams()
            users   = self.client.get_users()
            self.after(0, self._populate, streams, users)
        except Exception as e:
            self.after(0, self._load_err, str(e))

    def _populate(self, streams: Dict, users: List) -> None:
        self._stop_spinner()
        self.streams = streams; self.users = users
        self.perms_cache.clear(); self.sel_user_ids.clear()
        self._rebuild_users(users)
        self._rebuild_cats(streams)
        self._rebuild_streams(streams)
        self._log(f"✓  {len(streams)} streams · {len(users)} utilisateurs [{self.env}]", "ok")
        self._set_status(f"[{self.env}]  {len(streams)} streams · {len(users)} utilisateurs")

    def _load_err(self, msg: str) -> None:
        self._stop_spinner()
        self._log(f"✗  Erreur connexion : {msg}", "err")
        self._set_status("Erreur de connexion")

    # ── Rebuild ───────────────────────────────────────────────────────────────

    def _rebuild_users(self, users: List) -> None:
        self.user_lb.delete(0, tk.END)
        self._user_id_map = {}
        for i, u in enumerate(sorted(users, key=lambda x: x["username"].lower())):
            full = f"  {u['username']}" + (f"  ({u['full_name']})" if u["full_name"] else "")
            self.user_lb.insert(tk.END, full)
            self._user_id_map[i] = u["id"]

    def _rebuild_cats(self, streams: Dict) -> None:
        cats: Set[str] = set()
        for t in streams.values():
            c = extract_category(t)
            if c: cats.add(c)
        self.categories = sorted(cats, key=str.lower)
        self.cat_lb.delete(0, tk.END)
        for c in self.categories:
            self.cat_lb.insert(tk.END, f"  [{c}]")

    def _rebuild_streams(self, streams: Dict) -> None:
        self.stream_lb.delete(0, tk.END)
        self.stream_id_map = {}
        for i, (sid, title) in enumerate(sorted(streams.items(), key=lambda x: x[1].lower())):
            self.stream_lb.insert(tk.END, f"  {title}")
            self.stream_id_map[i] = sid

    # ── Filtres ───────────────────────────────────────────────────────────────

    def _filter_users(self, *_) -> None:
        q = self.user_search_var.get().lower()
        self._rebuild_users([u for u in self.users
                             if q in u["username"].lower() or q in u["full_name"].lower()])

    def _filter_streams(self, *_) -> None:
        q = self.stream_search_var.get().lower()
        self._rebuild_streams({s:t for s,t in self.streams.items() if q in t.lower()})

    # ── Sélections ────────────────────────────────────────────────────────────

    def _on_cat_sel(self, _=None) -> None:
        cats = {self.categories[i] for i in self.cat_lb.curselection()}
        if not cats: return
        self.stream_lb.selection_clear(0, tk.END)
        for i in range(self.stream_lb.size()):
            if extract_category(self.stream_lb.get(i).strip()) in cats:
                self.stream_lb.selection_set(i)
        self._on_stream_sel()
        self._log(f"  Catégorie(s) {sorted(cats)} → {len(self.stream_lb.curselection())} stream(s)", "info")

    def _sel_all_cats(self) -> None:
        self.cat_lb.select_set(0, tk.END); self._on_cat_sel()

    def _desel_cats(self) -> None:
        self.cat_lb.selection_clear(0, tk.END)

    def _sel_all_streams(self) -> None:
        self.stream_lb.select_set(0, tk.END); self._on_stream_sel()

    def _desel_streams(self) -> None:
        self.stream_lb.selection_clear(0, tk.END); self._on_stream_sel()

    def _on_stream_sel(self, _=None) -> None:
        n = len(self.stream_lb.curselection())
        self.stream_count_lbl.configure(text=f"{n} sélectionné(s)" if n else "")

    def _on_users_sel(self, _=None) -> None:
        self.sel_user_ids = [self._user_id_map[i] for i in self.user_lb.curselection()]
        n = len(self.sel_user_ids)
        if n:
            names = [self.user_lb.get(i).split("(")[0].strip() for i in self.user_lb.curselection()]
            preview = ", ".join(names[:3]) + ("…" if n > 3 else "")
            self.user_sel_var.set(f"{n} sélectionné(s) : {preview}")
        else:
            self.user_sel_var.set("Aucun utilisateur sélectionné")
        for uid in self.sel_user_ids:
            if uid not in self.perms_cache:
                threading.Thread(target=lambda u=uid: self.perms_cache.update({u: self.client.get_user_permissions(u)}),
                                 daemon=True).start()

    def _on_stream_dbl(self, event) -> None:
        idx = self.stream_lb.nearest(event.y)
        if idx < 0 or idx not in self.stream_id_map: return
        sid   = self.stream_id_map[idx]
        title = self.stream_lb.get(idx).strip()
        StreamDetailWindow(self, title, sid, self.client, self.users)

    # ── Guards ────────────────────────────────────────────────────────────────

    def _guard(self) -> bool:
        if not self.sel_user_ids:
            messagebox.showwarning("Sélection manquante",
                                   "Veuillez sélectionner au moins un utilisateur.", parent=self)
            return False
        if not self.stream_lb.curselection():
            messagebox.showwarning("Sélection manquante",
                                   "Veuillez sélectionner au moins un stream.", parent=self)
            return False
        return True

    def _sel_streams(self) -> List[Tuple[str,str]]:
        return [(self.stream_id_map[i], self.stream_lb.get(i).strip())
                for i in self.stream_lb.curselection()]

    def _uname(self, uid: str) -> str:
        return next((u["username"] for u in self.users if u["id"] == uid), uid)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _show_permissions(self) -> None:
        if not self._guard(): return
        self._log("── Inspection des permissions ──────────", "head")
        for uid in self.sel_user_ids:
            perms = self.perms_cache.get(uid, {})
            self._log(f"  👤 {self._uname(uid)}", "info")
            for sid, title in self._sel_streams():
                p = self.client.user_perm_on_stream(perms, sid)
                if p:
                    self._log(f"      {perm_icon(p)} {title}  →  {p}", "ok")
                else:
                    self._log(f"      ○  {title}  →  aucune permission", "skip")

    def _apply_permissions(self) -> None:
        if not self._guard(): return
        cap = self.perm_var.get()
        nu  = len(self.sel_user_ids)
        ns  = len(self.stream_lb.curselection())
        self._log(f"── Appliquer « {cap} »  {nu} user(s) × {ns} stream(s) ──", "head")
        threading.Thread(target=self._run_apply, args=(cap,), daemon=True).start()

    def _run_apply(self, cap: str) -> None:
        ok = skip = err = 0
        streams = self._sel_streams()
        for uid in self.sel_user_ids:
            uname = self._uname(uid)
            perms = self.perms_cache.get(uid, {})
            for sid, title in streams:
                if self.client.user_perm_on_stream(perms, sid) == cap:
                    self.after(0, self._log, f"  ⊘  [{uname}] {title}", "skip"); skip += 1; continue
                s, msg = self.client.set_permission(sid, uid, cap)
                if s:
                    self.after(0, self._log, f"  ✓  [{uname}] {title}", "ok"); ok += 1
                else:
                    self.after(0, self._log, f"  ✗  [{uname}] {title}  —  {msg}", "err"); err += 1
            if ok: self.perms_cache[uid] = self.client.get_user_permissions(uid)

        r = f"{ok} appliquées  ·  {skip} ignorées  ·  {err} erreurs"
        self.after(0, self._log, f"  → {r}", "ok" if not err else "warn")
        self.after(0, (messagebox.showinfo if not err else messagebox.showwarning), "Résultat", r)

    def _remove_permissions(self) -> None:
        if not self._guard(): return
        n = len(self.sel_user_ids) * len(self.stream_lb.curselection())
        if not messagebox.askyesno("Confirmer la suppression",
                                   f"Supprimer la permission pour {n} combinaison(s) ?",
                                   parent=self): return
        self._log("── Suppression des permissions ─────────", "head")
        threading.Thread(target=self._run_remove, daemon=True).start()

    def _run_remove(self) -> None:
        ok = err = 0
        for uid in self.sel_user_ids:
            uname = self._uname(uid)
            for sid, title in self._sel_streams():
                s, msg = self.client.remove_permission(sid, uid)
                if s:
                    self.after(0, self._log, f"  ✓  [{uname}] {title}", "ok"); ok += 1
                else:
                    self.after(0, self._log, f"  ✗  [{uname}] {title}  —  {msg}", "err"); err += 1
            if ok: self.perms_cache[uid] = self.client.get_user_permissions(uid)
        self.after(0, self._log, f"  → {ok} supprimées  ·  {err} erreurs", "ok" if not err else "warn")

    # ── Logs ──────────────────────────────────────────────────────────────────

    def _log(self, msg: str, tag: str = "skip") -> None:
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert(tk.END, f"[{ts}] ", "ts")
        self.log_box.insert(tk.END, f"{msg}\n", tag)
        self.log_box.see(tk.END)
        self.log_box.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", tk.END)
        self.log_box.configure(state="disabled")

    # ── Status / Spinner ──────────────────────────────────────────────────────

    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)

    def _start_spinner(self) -> None:
        self._spinning = True
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        def tick(i=0):
            if self._spinning:
                self.spinner_var.set(frames[i % len(frames)])
                self.after(80, tick, i+1)
            else:
                self.spinner_var.set("●")
        tick()

    def _stop_spinner(self) -> None:
        self._spinning = False
        self.after(100, lambda: self.spinner_var.set("●"))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    app = GraylogApp()
    app.mainloop()

if __name__ == "__main__":
    main()
