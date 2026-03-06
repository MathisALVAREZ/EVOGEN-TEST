# -*- coding: utf-8 -*-
"""Graylog Permission Manager"""

import base64
import csv
import logging
import os
import re
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import urllib3
from urllib.parse import quote

try:
    from secret import GRAYLOG_URL_PROD, GRAYLOG_URL_RECETTE
except ImportError:
    raise SystemExit(
        "Fichier 'secret.py' introuvable.\n"
        "Créez-le avec GRAYLOG_URL_PROD et GRAYLOG_URL_RECETTE."
    )

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── Constantes ───────────────────────────────────────────────────────────────
PERMISSIONS:     List[str] = ["view", "manage", "own"]
GRN_PREFIX:      str       = "grn::::stream:"
GRN_USER_PREFIX: str       = "grn::::user:"
CATEGORY_RE                = re.compile(r"^\[([^\]#][^\]]*)\]")
LOG_FILE:        str       = "graylog_history.log"

# ─── Palette  ──────────────────────────────────────────────────────────
C = {
    "bg":           "#F5F7FA",
    "bg_white":     "#FFFFFF",
    "bg_panel":     "#EEF1F6",
    "sidebar":      "#1B3A6B",
    "sidebar_dark": "#122849",
    "sidebar_item": "#223F73",
    "green":        "#00A878",
    "green_light":  "#E6F6F2",
    "green_dark":   "#007A57",
    "blue":         "#1B3A6B",
    "blue_light":   "#E8EEF8",
    "blue_mid":     "#2D5AA0",
    "text":         "#1A2340",
    "text2":        "#4A5568",
    "text3":        "#8896A8",
    "text_light":   "#FFFFFF",
    "view":         "#2D5AA0",
    "view_bg":      "#E8EEF8",
    "manage":       "#D97706",
    "manage_bg":    "#FEF3C7",
    "own":          "#DC2626",
    "own_bg":       "#FEE2E2",
    "prod":         "#00A878",
    "prod_bg":      "#E6F6F2",
    "recette":      "#D97706",
    "recette_bg":   "#FEF3C7",
    "border":       "#D8E0EC",
    "border2":      "#C5D0E0",
    "select":       "#D4E3FF",
    "red":          "#DC2626",
    "success":      "#00A878",
    "warning":      "#D97706",
    "error":        "#DC2626",
    "progress_bg":  "#E8EEF8",
    "progress_fg":  "#00A878",
}

FONT_LABEL  = ("Segoe UI", 10)
FONT_BOLD   = ("Segoe UI", 10, "bold")
FONT_SMALL  = ("Segoe UI", 9)
FONT_MONO   = ("Consolas", 9)
FONT_HEADER = ("Segoe UI", 11, "bold")
FONT_BIG    = ("Segoe UI", 14, "bold")
FONT_HUGE   = ("Segoe UI", 22, "bold")


# ─── Client API ───────────────────────────────────────────────────────────────

class AuthError(Exception):
    pass

class NotAdminError(Exception):
    pass

class GraylogClient:
    def __init__(self, url: str, username: str, password: str) -> None:
        self.base_url = url.rstrip("/")
        self.username = username
        self.session  = requests.Session()
        self.session.verify = False
        b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.session.headers.update({
            "Authorization":  f"Basic {b64}",
            "Accept":         "application/json",
            "Content-Type":   "application/json",
            "X-Requested-By": "graylog-manager",
        })

    # ── Auth & Admin check ────────────────────────────────────────────────────

    def check_auth_and_admin(self) -> Dict[str, Any]:
        """
        Vérifie les credentials et le rôle admin.
        Stratégie multi-endpoints pour compatibilité toutes versions Graylog.
        """
        # ── Étape 1 : vérifier que les credentials sont valides ───────────────
        # /api/system est accessible à tout utilisateur authentifié
        auth_endpoints = [
            "/api/users/me",
            "/api/system/sessions",
            "/api/system",
        ]
        user: Dict[str, Any] = {}
        authed = False

        for ep in auth_endpoints:
            try:
                r = self.session.get(f"{self.base_url}{ep}", timeout=10)
            except requests.RequestException as e:
                raise AuthError(f"Impossible de joindre Graylog : {e}")

            if r.status_code == 401:
                raise AuthError("Identifiants incorrects.")
            if r.status_code == 403:
                raise AuthError("Accès refusé (identifiants valides mais permissions insuffisantes).")
            if r.status_code == 404:
                continue  # essayer le suivant
            if r.ok:
                try:
                    user = r.json()
                except Exception:
                    user = {}
                authed = True
                break

        if not authed:
            raise AuthError(
                "Impossible de joindre l'API Graylog.\n"
                "Vérifiez l'URL dans secret.py et que Graylog est accessible."
            )

        # ── Étape 2 : vérifier le rôle admin ─────────────────────────────────
        # Essayer plusieurs façons de récupérer les rôles
        is_admin = False

        # Méthode A : rôles dans la réponse /api/users/me
        roles = user.get("roles", [])
        if any("admin" in str(r).lower() for r in roles):
            is_admin = True

        # Méthode B : endpoint dédié /api/users/{username}
        if not is_admin:
            try:
                r2 = self.session.get(f"{self.base_url}/api/users/{self.username}", timeout=10)
                if r2.ok:
                    u2    = r2.json()
                    roles = u2.get("roles", [])
                    if any("admin" in str(r).lower() for r in roles):
                        is_admin = True
            except Exception:
                pass

        # Méthode C : GET /api/authz/roles/user/{username}
        if not is_admin:
            try:
                r3 = self.session.get(
                    f"{self.base_url}/api/authz/roles/user/{self.username}", timeout=10
                )
                if r3.ok:
                    roles_data = r3.json()
                    all_roles  = roles_data if isinstance(roles_data, list) else roles_data.get("roles", [])
                    if any("admin" in str(r).lower() for r in all_roles):
                        is_admin = True
            except Exception:
                pass

        # Méthode D : GET /api/roles — lister les rôles de l'utilisateur
        if not is_admin:
            try:
                r4 = self.session.get(f"{self.base_url}/api/roles", timeout=10)
                if r4.ok:
                    # Si on peut lister les rôles admin, c'est qu'on est admin
                    is_admin = True
            except Exception:
                pass

        if not is_admin:
            raise NotAdminError(
                f"L'utilisateur « {self.username} » n'a pas le rôle Admin.\n"
                "Seuls les administrateurs peuvent utiliser cet outil."
            )

        logger.info("Authentification réussie pour %s", self.username)
        return user

    # ── Requêtes génériques ───────────────────────────────────────────────────

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

    # ── Données ───────────────────────────────────────────────────────────────

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

    # ── Partages ──────────────────────────────────────────────────────────────

    def _prepare(self, grn: str) -> Optional[Dict]:
        enc = quote(grn, safe="")
        url = f"{self.base_url}/api/authz/shares/entities/{enc}/prepare"
        try:
            r = self.session.post(url, json={}, timeout=15)
            return r.json() if r.status_code in (200, 201) else None
        except Exception as e:
            logger.error("prepare: %s", e); return None

    def _post_shares(self, grn: str, grantees: Dict[str, str]) -> Tuple[bool, str]:
        enc = quote(grn, safe="")
        url = f"{self.base_url}/api/authz/shares/entities/{enc}"
        try:
            r = self.session.post(url, json={"selected_grantee_capabilities": grantees}, timeout=15)
            return (True, "OK") if r.status_code in (200,201,204) else (False, f"HTTP {r.status_code}: {r.text[:300]}")
        except Exception as e:
            return False, str(e)

    def set_permission(self, sid: str, uid: str, cap: str) -> Tuple[bool, str]:
        grn = f"{GRN_PREFIX}{sid}"; ugrn = f"{GRN_USER_PREFIX}{uid}"
        p   = self._prepare(grn)
        if p is None: return False, "prepare failed"
        ex  = dict(p.get("selected_grantee_capabilities") or p.get("grantees") or {})
        ex[ugrn] = cap
        ok, msg = self._post_shares(grn, ex)
        return (True, "OK") if ok else (False, msg)

    def remove_permission(self, sid: str, uid: str) -> Tuple[bool, str]:
        grn = f"{GRN_PREFIX}{sid}"; ugrn = f"{GRN_USER_PREFIX}{uid}"
        p   = self._prepare(grn)
        if p is None: return False, "prepare failed"
        ex  = {k:v for k,v in (p.get("selected_grantee_capabilities") or p.get("grantees") or {}).items() if k != ugrn}
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

def log_to_file(username: str, env: str, action: str, details: str) -> None:
    """Écrit une ligne horodatée dans le fichier d'historique."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [{env}] [{username}] {action} | {details}\n")
    except Exception:
        pass


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
                 font=FONT_SMALL, padx=10, pady=5).pack()

    def _hide(self, _=None):
        if self.tw: self.tw.destroy(); self.tw = None


# ─── Barre de progression ─────────────────────────────────────────────────────

class ProgressBar(tk.Frame):
    """Barre de progression custom aux couleurs ."""
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["progress_bg"], height=6, **kw)
        self.pack_propagate(False)
        self._bar = tk.Frame(self, bg=C["progress_fg"], height=6)
        self._bar.place(relx=0, rely=0, relwidth=0, relheight=1)
        self._val = 0.0

    def set(self, value: float) -> None:
        """value entre 0.0 et 1.0"""
        self._val = max(0.0, min(1.0, value))
        self._bar.place(relwidth=self._val)
        self.update_idletasks()

    def reset(self) -> None:
        self.set(0.0)


# ─── Fenêtre Login ────────────────────────────────────────────────────────────

class LoginWindow(tk.Tk):
    """Fenêtre de connexion affichée au démarrage."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Connexion — Graylog Permission Manager")
        self.geometry("460x560")
        self.resizable(False, False)
        self.configure(bg=C["bg_white"])

        self.result: Optional[Tuple[str, str]] = None  # (username, password) si succès
        self._build()
        self.eval('tk::PlaceWindow . center')

    def _build(self) -> None:
        
        hdr = tk.Frame(self, bg=C["sidebar"], height=140)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="GRAYLOG", font=("Segoe UI", 26, "bold"),
                 fg=C["text_light"], bg=C["sidebar"]).pack(pady=(28, 0))
        tk.Label(hdr, text="Graylog Permission Manager By Alvarez Mathis",
                 font=("Segoe UI", 10), fg="#8BAAD4", bg=C["sidebar"]).pack()

        # Barre verte
        tk.Frame(self, bg=C["green"], height=3).pack(fill="x")

        # Formulaire
        form = tk.Frame(self, bg=C["bg_white"], padx=48, pady=32)
        form.pack(fill="both", expand=True)

        tk.Label(form, text="Connexion", font=("Segoe UI", 16, "bold"),
                 fg=C["text"], bg=C["bg_white"]).pack(anchor="w", pady=(0, 4))
        tk.Label(form, text="Connectez-vous avec votre compte Graylog",
                 font=FONT_SMALL, fg=C["text3"], bg=C["bg_white"]).pack(anchor="w", pady=(0, 24))

        # Champ username
        tk.Label(form, text="Nom d'utilisateur", font=FONT_BOLD,
                 fg=C["text2"], bg=C["bg_white"]).pack(anchor="w")
        self.user_var = tk.StringVar()
        self._input_field(form, self.user_var, show="")
        tk.Frame(form, height=16, bg=C["bg_white"]).pack()

        # Champ password
        tk.Label(form, text="Mot de passe", font=FONT_BOLD,
                 fg=C["text2"], bg=C["bg_white"]).pack(anchor="w")
        self.pass_var = tk.StringVar()
        self._input_field(form, self.pass_var, show="●")

        # Environnement
        tk.Frame(form, height=20, bg=C["bg_white"]).pack()
        tk.Label(form, text="Environnement", font=FONT_BOLD,
                 fg=C["text2"], bg=C["bg_white"]).pack(anchor="w")
        env_f = tk.Frame(form, bg=C["bg_white"])
        env_f.pack(fill="x", pady=(6, 0))
        self.env_var = tk.StringVar(value="PROD")
        for env, color in [("PROD", C["prod"]), ("RECETTE", C["recette"])]:
            rb = tk.Radiobutton(env_f, text=f"  {env}", variable=self.env_var, value=env,
                                font=FONT_BOLD, fg=C["text2"], bg=C["bg_white"],
                                selectcolor=C["bg_white"], activebackground=C["bg_white"],
                                activeforeground=color, relief="flat", cursor="hand2")
            rb.pack(side="left", padx=(0, 20))

        # Message d'erreur
        self.err_var = tk.StringVar()
        tk.Label(form, textvariable=self.err_var, font=FONT_SMALL,
                 fg=C["error"], bg=C["bg_white"], wraplength=340).pack(pady=(12, 0))

        # Bouton connexion
        tk.Frame(form, height=8, bg=C["bg_white"]).pack()
        self.btn = tk.Button(form, text="Se connecter", font=FONT_BOLD,
                             fg=C["text_light"], bg=C["green"],
                             activeforeground=C["text_light"], activebackground=C["green_dark"],
                             relief="flat", bd=0, cursor="hand2",
                             pady=12, command=self._try_login)
        self.btn.pack(fill="x")
        self.btn.bind("<Enter>", lambda e: self.btn.configure(bg=C["green_dark"]))
        self.btn.bind("<Leave>", lambda e: self.btn.configure(bg=C["green"]))

        # Spinner
        self.spin_var = tk.StringVar()
        tk.Label(form, textvariable=self.spin_var, font=("Segoe UI", 12),
                 fg=C["green"], bg=C["bg_white"]).pack(pady=(8, 0))

        # Bind Enter
        self.bind("<Return>", lambda _: self._try_login())

    def _input_field(self, parent, var: tk.StringVar, show: str) -> tk.Entry:
        frame = tk.Frame(parent, bg=C["bg_panel"], pady=1)
        frame.pack(fill="x", pady=(6, 0))
        e = tk.Entry(frame, textvariable=var, show=show,
                     font=FONT_LABEL, bg=C["bg_panel"], fg=C["text"],
                     relief="flat", bd=0, insertbackground=C["blue"])
        e.pack(fill="x", padx=12, pady=10)
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x")
        return e

    def _try_login(self) -> None:
        username = self.user_var.get().strip()
        password = self.pass_var.get()
        env      = self.env_var.get()

        if not username or not password:
            self.err_var.set("Veuillez remplir tous les champs.")
            return

        self.btn.configure(state="disabled")
        self.err_var.set("")
        self._start_spin()
        url = GRAYLOG_URL_PROD if env == "PROD" else GRAYLOG_URL_RECETTE
        threading.Thread(target=self._do_login,
                         args=(username, password, url, env), daemon=True).start()

    def _do_login(self, username: str, password: str, url: str, env: str) -> None:
        try:
            client = GraylogClient(url, username, password)
            client.check_auth_and_admin()
            self.after(0, self._login_ok, client, env)
        except NotAdminError as e:
            self.after(0, self._login_fail, str(e), close=True)
        except AuthError as e:
            self.after(0, self._login_fail, str(e))
        except Exception as e:
            self.after(0, self._login_fail, f"Erreur inattendue : {e}")

    def _login_ok(self, client: "GraylogClient", env: str) -> None:
        self._stop_spin()
        self.result = client
        self._initial_env = env
        self.destroy()

    def _login_fail(self, msg: str, close: bool = False) -> None:
        self._stop_spin()
        self.btn.configure(state="normal")
        if close:
            messagebox.showerror(
                "Accès refusé", msg, parent=self
            )
            self.destroy()
        else:
            self.err_var.set(msg)

    def _start_spin(self) -> None:
        self._spinning = True
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        def tick(i=0):
            if not self._spinning:
                return
            try:
                self.spin_var.set(frames[i % len(frames)])
                self.after(80, tick, i+1)
            except tk.TclError:
                pass  # fenêtre détruite, on arrête silencieusement
        tick()

    def _stop_spin(self) -> None:
        self._spinning = False


# ─── Popup : droits d'un stream ───────────────────────────────────────────────

class StreamDetailWindow(tk.Toplevel):
    def __init__(self, parent, title: str, sid: str,
                 client: GraylogClient, users: List[Dict]) -> None:
        super().__init__(parent)
        self.title(f"Droits — {title}")
        self.configure(bg=C["bg"])
        self.geometry("600x500")
        self.resizable(True, True)
        self.grab_set()
        self._grn_to_user = {f"{GRN_USER_PREFIX}{u['id']}": u for u in users}
        self._build(title, sid, client)

    def _build(self, title: str, sid: str, client: GraylogClient) -> None:
        hdr = tk.Frame(self, bg=C["sidebar"], pady=20, padx=24)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Droits sur le stream", font=FONT_SMALL,
                 fg="#AABBDD", bg=C["sidebar"]).pack(anchor="w")
        tk.Label(hdr, text=title, font=FONT_BIG,
                 fg=C["text_light"], bg=C["sidebar"]).pack(anchor="w", pady=(2,0))
        tk.Frame(self, bg=C["green"], height=3).pack(fill="x")

        content = tk.Frame(self, bg=C["bg"], padx=20, pady=16)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(1, weight=1)

        hrow = tk.Frame(content, bg=C["bg_panel"])
        hrow.pack(fill="x", pady=(0, 4))
        for txt, w in [("Utilisateur", 26), ("Nom complet", 22), ("Permission", 14)]:
            tk.Label(hrow, text=txt, font=FONT_BOLD, fg=C["text3"],
                     bg=C["bg_panel"], anchor="w", padx=12, pady=8, width=w).pack(side="left")

        canvas = tk.Canvas(content, bg=C["bg"], highlightthickness=0)
        sb     = ttk.Scrollbar(content, orient="vertical", command=canvas.yview)
        self.inner = tk.Frame(canvas, bg=C["bg"])
        self.inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

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
        order = {"own":0,"manage":1,"view":2}
        for i, (grn, cap) in enumerate(sorted(grantees.items(),
                                               key=lambda x: (order.get(x[1],9), x[0]))):
            u    = self._grn_to_user.get(grn, {})
            bg   = C["bg_white"] if i % 2 == 0 else C["bg"]
            row  = tk.Frame(self.inner, bg=bg, pady=2)
            row.pack(fill="x")
            tk.Label(row, text=u.get("username", grn.split(":")[-1]),
                     font=FONT_BOLD, fg=C["text"], bg=bg, anchor="w",
                     padx=12, width=26).pack(side="left")
            tk.Label(row, text=u.get("full_name","—"), font=FONT_LABEL,
                     fg=C["text2"], bg=bg, anchor="w", padx=8, width=22).pack(side="left")
            tk.Label(tk.Frame(row, bg=bg), text=f"  {perm_icon(cap)} {cap}  ",
                     font=("Segoe UI", 9, "bold"), fg=perm_color(cap),
                     bg=perm_bg(cap), padx=4, pady=3).pack(side="left", padx=8, pady=4)

        tk.Frame(self.inner, bg=C["border"], height=1).pack(fill="x", pady=6, padx=8)
        tk.Label(self.inner, text=f"{len(grantees)} entrée(s)",
                 font=FONT_SMALL, fg=C["text3"], bg=C["bg"]).pack(anchor="e", padx=14, pady=4)


# ─── Popup : Copier permissions ───────────────────────────────────────────────

class CopyPermsWindow(tk.Toplevel):
    """Copie toutes les permissions stream d'un user source vers un/plusieurs users cibles."""

    def __init__(self, parent: "GraylogApp") -> None:
        super().__init__(parent)
        self.app = parent
        self.title("Copier les permissions")
        self.configure(bg=C["bg"])
        self.geometry("620x560")
        self.resizable(True, True)
        self.grab_set()
        self._build()

    def _build(self) -> None:
        hdr = tk.Frame(self, bg=C["sidebar"], pady=18, padx=24)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Copier les permissions",
                 font=FONT_BIG, fg=C["text_light"], bg=C["sidebar"]).pack(anchor="w")
        tk.Label(hdr, text="Copie tous les accès stream d'un utilisateur source vers des cibles",
                 font=FONT_SMALL, fg="#8BAAD4", bg=C["sidebar"]).pack(anchor="w", pady=(2,0))
        tk.Frame(self, bg=C["green"], height=3).pack(fill="x")

        body = tk.Frame(self, bg=C["bg"], padx=24, pady=16)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(3, weight=1)

        users_sorted = sorted(self.app.users, key=lambda u: u["username"].lower())
        unames = [f"{u['username']}  ({u['full_name']})" for u in users_sorted]
        self._uid_list = [u["id"] for u in users_sorted]

        # Source
        tk.Label(body, text="Utilisateur SOURCE", font=FONT_BOLD,
                 fg=C["text2"], bg=C["bg"]).grid(row=0, column=0, sticky="w", pady=(0,4))
        self.src_var = tk.StringVar()
        self.src_cb = ttk.Combobox(body, textvariable=self.src_var,
                                    values=unames, state="readonly", font=FONT_LABEL)
        self.src_cb.grid(row=1, column=0, sticky="ew", pady=(0,16))

        # Cibles
        tk.Label(body, text="Utilisateurs CIBLES  (Ctrl+clic = multi-sélection)",
                 font=FONT_BOLD, fg=C["text2"], bg=C["bg"]).grid(row=2, column=0, sticky="w", pady=(0,4))

        lb_f = tk.Frame(body, bg=C["bg_white"])
        lb_f.grid(row=3, column=0, sticky="nsew")
        lb_f.rowconfigure(0, weight=1); lb_f.columnconfigure(0, weight=1)
        self.tgt_lb = tk.Listbox(lb_f, selectmode=tk.MULTIPLE, font=FONT_LABEL,
                                  bg=C["bg_white"], fg=C["text"],
                                  selectbackground=C["blue_light"], selectforeground=C["blue"],
                                  activestyle="none", highlightthickness=0, relief="flat",
                                  exportselection=False, cursor="hand2")
        self.tgt_lb.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(lb_f, command=self.tgt_lb.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tgt_lb.configure(yscrollcommand=sb.set)
        for name in unames:
            self.tgt_lb.insert(tk.END, f"  {name}")

        # Progress + status
        self.prog = ProgressBar(body)
        self.prog.grid(row=4, column=0, sticky="ew", pady=(12,4))
        self.status_var = tk.StringVar(value="")
        tk.Label(body, textvariable=self.status_var, font=FONT_SMALL,
                 fg=C["text3"], bg=C["bg"]).grid(row=5, column=0, sticky="w")

        # Bouton
        btn = tk.Button(body, text="Copier les permissions", font=FONT_BOLD,
                        fg=C["text_light"], bg=C["green"],
                        activeforeground=C["text_light"], activebackground=C["green_dark"],
                        relief="flat", bd=0, cursor="hand2", pady=10, command=self._run)
        btn.grid(row=6, column=0, sticky="ew", pady=(12,0))
        btn.bind("<Enter>", lambda e: btn.configure(bg=C["green_dark"]))
        btn.bind("<Leave>", lambda e: btn.configure(bg=C["green"]))
        self.btn = btn

    def _run(self) -> None:
        if not self.src_var.get():
            messagebox.showwarning("Manque", "Sélectionnez un utilisateur source.", parent=self)
            return
        if not self.tgt_lb.curselection():
            messagebox.showwarning("Manque", "Sélectionnez au moins un utilisateur cible.", parent=self)
            return

        src_idx = self.src_cb.current()
        if src_idx < 0:
            messagebox.showwarning("Manque", "Sélectionnez un utilisateur source.", parent=self)
            return
        src_uid = self._uid_list[src_idx]
        tgt_ids = [self._uid_list[i] for i in self.tgt_lb.curselection()]

        self.btn.configure(state="disabled")
        threading.Thread(target=self._do_copy, args=(src_uid, tgt_ids), daemon=True).start()

    def _do_copy(self, src_uid: str, tgt_ids: List[str]) -> None:
        client  = self.app.client
        streams = self.app.streams
        src_perms = client.get_user_permissions(src_uid)
        src_uname = self.app._uname(src_uid)

        total = len(tgt_ids) * len(streams)
        done  = 0

        for tgt_uid in tgt_ids:
            tgt_uname = self.app._uname(tgt_uid)
            ok = err = 0
            for sid, stitle in streams.items():
                cap = client.user_perm_on_stream(src_perms, sid)
                if cap:
                    s, msg = client.set_permission(sid, tgt_uid, cap)
                    if s: ok += 1
                    else: err += 1
                done += 1
                self.after(0, self.prog.set, done / total)
                self.after(0, self.status_var.set,
                           f"[{tgt_uname}] {done}/{total} traités…")

            log_to_file(client.username, self.app.env,
                        "COPY_PERMS",
                        f"source={src_uname} → cible={tgt_uname} | {ok} ok, {err} erreurs")
            self.app.after(0, self.app._log,
                           f"  ✓ Copie {src_uname} → {tgt_uname} : {ok} permissions", "ok")

        self.after(0, self.status_var.set, "✓ Copie terminée !")
        self.after(0, self.btn.configure, {"state": "normal"})


# ─── Popup : Comparer deux utilisateurs ──────────────────────────────────────

class CompareWindow(tk.Toplevel):
    """Compare les permissions stream de deux utilisateurs côte à côte."""

    def __init__(self, parent: "GraylogApp") -> None:
        super().__init__(parent)
        self.app = parent
        self.title("Comparer deux utilisateurs")
        self.configure(bg=C["bg"])
        self.geometry("900x600")
        self.resizable(True, True)
        self.grab_set()
        self._build()

    def _build(self) -> None:
        hdr = tk.Frame(self, bg=C["sidebar"], pady=18, padx=24)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Comparaison des permissions",
                 font=FONT_BIG, fg=C["text_light"], bg=C["sidebar"]).pack(anchor="w")
        tk.Label(hdr, text="Visualisez les différences de droits entre deux utilisateurs",
                 font=FONT_SMALL, fg="#8BAAD4", bg=C["sidebar"]).pack(anchor="w", pady=(2,0))
        tk.Frame(self, bg=C["green"], height=3).pack(fill="x")

        top = tk.Frame(self, bg=C["bg"], padx=24, pady=12)
        top.pack(fill="x")
        top.columnconfigure(1, weight=1); top.columnconfigure(3, weight=1)

        users_sorted = sorted(self.app.users, key=lambda u: u["username"].lower())
        unames = [f"{u['username']}  ({u['full_name']})" for u in users_sorted]
        self._uid_list = [u["id"] for u in users_sorted]

        tk.Label(top, text="Utilisateur A", font=FONT_BOLD,
                 fg=C["blue_mid"], bg=C["bg"]).grid(row=0, column=0, sticky="w", padx=(0,8))
        self.ua_var = tk.StringVar()
        self.ua_cb = ttk.Combobox(top, textvariable=self.ua_var, values=unames,
                                   state="readonly", font=FONT_LABEL)
        self.ua_cb.grid(row=0, column=1, sticky="ew", padx=(0,16))

        tk.Label(top, text="Utilisateur B", font=FONT_BOLD,
                 fg=C["manage"], bg=C["bg"]).grid(row=0, column=2, sticky="w", padx=(0,8))
        self.ub_var = tk.StringVar()
        self.ub_cb = ttk.Combobox(top, textvariable=self.ub_var, values=unames,
                                   state="readonly", font=FONT_LABEL)
        self.ub_cb.grid(row=0, column=3, sticky="ew")

        btn = tk.Button(top, text="Comparer", font=FONT_BOLD,
                        fg=C["text_light"], bg=C["blue_mid"],
                        activeforeground=C["text_light"], activebackground=C["blue"],
                        relief="flat", bd=0, cursor="hand2",
                        padx=16, pady=6, command=self._run)
        btn.grid(row=0, column=4, padx=(16,0))

        # Légende
        leg = tk.Frame(self, bg=C["bg_panel"], padx=24, pady=6)
        leg.pack(fill="x")
        for txt, bg, fg in [
            ("  Identique  ", C["green_light"], C["green_dark"]),
            ("  A seulement  ", "#DBEAFE", C["blue_mid"]),
            ("  B seulement  ", "#FEF3C7", C["manage"]),
            ("  Différent  ", "#FEE2E2", C["own"]),
            ("  Aucun droit  ", C["bg_panel"], C["text3"]),
        ]:
            tk.Label(leg, text=txt, font=FONT_SMALL, fg=fg, bg=bg,
                     padx=6, pady=3, relief="flat").pack(side="left", padx=4)

        # Table
        tbl_f = tk.Frame(self, bg=C["bg"])
        tbl_f.pack(fill="both", expand=True, padx=0, pady=0)
        tbl_f.rowconfigure(0, weight=1); tbl_f.columnconfigure(0, weight=1)

        canvas = tk.Canvas(tbl_f, bg=C["bg_white"], highlightthickness=0)
        sb_y   = ttk.Scrollbar(tbl_f, orient="vertical",   command=canvas.yview)
        sb_x   = ttk.Scrollbar(tbl_f, orient="horizontal", command=canvas.xview)
        self.tbl = tk.Frame(canvas, bg=C["bg_white"])
        self.tbl.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.tbl, anchor="nw")
        canvas.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.grid(row=0, column=1, sticky="ns")
        sb_x.grid(row=1, column=0, sticky="ew")
        canvas.grid(row=0, column=0, sticky="nsew")

        self.status_var = tk.StringVar(value="")
        tk.Label(self, textvariable=self.status_var, font=FONT_SMALL,
                 fg=C["text3"], bg=C["bg"], pady=4).pack()

    def _run(self) -> None:
        if not self.ua_var.get() or not self.ub_var.get():
            messagebox.showwarning("Manque", "Sélectionnez les deux utilisateurs.", parent=self)
            return
        ia = self.ua_cb.current(); ib = self.ub_cb.current()
        if ia < 0 or ib < 0:
            messagebox.showwarning("Manque", "Sélectionnez les deux utilisateurs.", parent=self)
            return
        ua = self._uid_list[ia];    ub = self._uid_list[ib]
        self.status_var.set("Chargement des permissions…")
        threading.Thread(target=self._do_compare, args=(ua, ub), daemon=True).start()

    def _do_compare(self, uid_a: str, uid_b: str) -> None:
        client  = self.app.client
        pa = client.get_user_permissions(uid_a)
        pb = client.get_user_permissions(uid_b)
        self.after(0, self._render, uid_a, uid_b, pa, pb)

    def _render(self, uid_a: str, uid_b: str,
                pa: Dict, pb: Dict) -> None:
        # Vider la table
        for w in self.tbl.winfo_children():
            w.destroy()

        na = self.app._uname(uid_a)
        nb = self.app._uname(uid_b)

        # En-têtes
        for col, txt, fg in [(0,"Stream",C["text"]),(1,f"👤 {na}",C["blue_mid"]),(2,f"👤 {nb}",C["manage"])]:
            tk.Label(self.tbl, text=txt, font=FONT_BOLD, fg=fg, bg=C["bg_panel"],
                     anchor="w", padx=14, pady=8, width=30 if col==0 else 14
            ).grid(row=0, column=col, sticky="ew", padx=1, pady=1)

        streams_sorted = sorted(self.app.streams.items(), key=lambda x: x[1].lower())
        for i, (sid, stitle) in enumerate(streams_sorted):
            ca = client_perm(pa, sid)
            cb = client_perm(pb, sid)
            bg_row = C["bg_white"] if i % 2 == 0 else C["bg"]

            if ca == cb and ca:
                row_bg = C["green_light"]
            elif ca and not cb:
                row_bg = "#DBEAFE"
            elif cb and not ca:
                row_bg = "#FEF3C7"
            elif ca and cb and ca != cb:
                row_bg = "#FEE2E2"
            else:
                row_bg = bg_row

            tk.Label(self.tbl, text=f"  {stitle}", font=FONT_LABEL, fg=C["text"],
                     bg=row_bg, anchor="w", padx=8, pady=4, width=30
            ).grid(row=i+1, column=0, sticky="ew", padx=1, pady=0)

            for col, cap in [(1, ca), (2, cb)]:
                if cap:
                    lbl = tk.Label(self.tbl,
                                   text=f"  {perm_icon(cap)} {cap}  ",
                                   font=("Segoe UI", 9, "bold"),
                                   fg=perm_color(cap), bg=row_bg,
                                   anchor="w", padx=8, pady=4, width=14)
                else:
                    lbl = tk.Label(self.tbl, text="  —  ", font=FONT_SMALL,
                                   fg=C["text3"], bg=row_bg, anchor="w",
                                   padx=8, pady=4, width=14)
                lbl.grid(row=i+1, column=col, sticky="ew", padx=1)

        self.status_var.set(f"Comparaison de {len(streams_sorted)} streams")


def client_perm(perms: Dict, sid: str) -> Optional[str]:
    return perms.get("context",{}).get("grantee_capabilities",{}).get(f"{GRN_PREFIX}{sid}")


# ─── Application principale ───────────────────────────────────────────────────

class GraylogApp(tk.Tk):

    def __init__(self, client: GraylogClient, initial_env: str) -> None:
        super().__init__()
        self.title("Graylog Permission Manager")
        self.geometry("1380x880")
        self.minsize(1100, 680)
        self.configure(bg=C["bg"])

        self.client         = client
        self.env            = initial_env
        self.streams:       Dict[str,str]       = {}
        self.stream_id_map: Dict[int,str]       = {}
        self.users:         List[Dict[str,str]] = []
        self._user_id_map:  Dict[int,str]       = {}
        self.categories:    List[str]           = []
        self.sel_user_ids:  List[str]           = []
        self.perms_cache:   Dict[str,Dict]      = {}
        self._spinning      = False

        self._style()
        self._build()
        self._load_async()

    # ── Style ─────────────────────────────────────────────────────────────────

    def _style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["text"], font=FONT_LABEL,
                    bordercolor=C["border"], troughcolor=C["bg_panel"])
        s.configure("TScrollbar", background=C["border"], troughcolor=C["bg_panel"],
                    arrowcolor=C["text3"], bordercolor=C["border"], relief="flat", width=8)
        s.map("TScrollbar", background=[("active", C["border2"])])
        s.configure("TCombobox", fieldbackground=C["bg_white"], foreground=C["text"],
                    selectbackground=C["blue_light"], selectforeground=C["blue"])

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()

    # ── SIDEBAR ───────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        sb = tk.Frame(self, bg=C["sidebar"], width=248)
        sb.grid(row=0, column=0, sticky="ns")
        sb.pack_propagate(False)

        # Logo
        logo = tk.Frame(sb, bg=C["sidebar"], pady=22, padx=20)
        logo.pack(fill="x")
        tk.Label(logo, text="GRAYLOG", font=("Segoe UI", 18, "bold"),
                 fg=C["text_light"], bg=C["sidebar"]).pack(anchor="w")
        tk.Label(logo, text="Permission Manager", font=("Segoe UI", 9),
                 fg="#8BAAD4", bg=C["sidebar"]).pack(anchor="w")
        tk.Label(logo, text=f"Connecté : {self.client.username}",
                 font=("Segoe UI", 8), fg="#5577AA", bg=C["sidebar"]).pack(anchor="w", pady=(4,0))

        tk.Frame(sb, bg=C["green"], height=2).pack(fill="x")

        # ENV
        env_s = tk.Frame(sb, bg=C["sidebar"], pady=14, padx=16)
        env_s.pack(fill="x")
        tk.Label(env_s, text="ENVIRONNEMENT", font=("Segoe UI", 8, "bold"),
                 fg="#6688AA", bg=C["sidebar"]).pack(anchor="w", pady=(0,8))
        self.btn_prod = self._env_btn(env_s, "PROD",    C["prod"],    "PROD")
        self.btn_rec  = self._env_btn(env_s, "RECETTE", C["recette"], "RECETTE")
        self.btn_prod.pack(fill="x", pady=2)
        self.btn_rec.pack(fill="x", pady=2)
        self._refresh_env_btns()

        tk.Frame(sb, bg="#243F6A", height=1).pack(fill="x")

        # Permission
        perm_s = tk.Frame(sb, bg=C["sidebar"], pady=14, padx=16)
        perm_s.pack(fill="x")
        tk.Label(perm_s, text="PERMISSION", font=("Segoe UI", 8, "bold"),
                 fg="#6688AA", bg=C["sidebar"]).pack(anchor="w", pady=(0,8))
        self.perm_var = tk.StringVar(value="view")
        self._perm_indicators = {}
        for perm in PERMISSIONS:
            self._perm_radio(perm_s, perm)

        tk.Frame(sb, bg="#243F6A", height=1).pack(fill="x")

        # Actions principales
        act_s = tk.Frame(sb, bg=C["sidebar"], pady=14, padx=16)
        act_s.pack(fill="x")
        tk.Label(act_s, text="ACTIONS", font=("Segoe UI", 8, "bold"),
                 fg="#6688AA", bg=C["sidebar"]).pack(anchor="w", pady=(0,8))
        self._sb_btn(act_s, "🔍  Inspecter",  C["blue_mid"], self._show_permissions).pack(fill="x", pady=2)
        self._sb_btn(act_s, "✅  Appliquer",  C["green"],    self._apply_permissions).pack(fill="x", pady=2)
        self._sb_btn(act_s, "🗑  Supprimer",  C["own"],      self._remove_permissions).pack(fill="x", pady=2)

        tk.Frame(sb, bg="#243F6A", height=1).pack(fill="x")

        # Outils
        tools_s = tk.Frame(sb, bg=C["sidebar"], pady=14, padx=16)
        tools_s.pack(fill="x")
        tk.Label(tools_s, text="OUTILS", font=("Segoe UI", 8, "bold"),
                 fg="#6688AA", bg=C["sidebar"]).pack(anchor="w", pady=(0,8))
        self._ghost_btn(tools_s, "⇄  Copier permissions",   self._open_copy).pack(fill="x", pady=1)
        self._ghost_btn(tools_s, "⚖  Comparer deux users",  self._open_compare).pack(fill="x", pady=1)
        self._ghost_btn(tools_s, "📄  Exporter CSV",         self._export_csv).pack(fill="x", pady=1)
        self._ghost_btn(tools_s, "↺  Rafraîchir",            self._load_async).pack(fill="x", pady=1)

        # Barre de progression globale
        prog_f = tk.Frame(sb, bg=C["sidebar"], padx=16, pady=8)
        prog_f.pack(fill="x")
        self.global_prog = ProgressBar(prog_f)
        self.global_prog.pack(fill="x")
        self.prog_label = tk.StringVar(value="")
        tk.Label(prog_f, textvariable=self.prog_label, font=("Segoe UI", 8),
                 fg="#6688AA", bg=C["sidebar"]).pack(anchor="w", pady=(4,0))

        # Status bas
        status_f = tk.Frame(sb, bg=C["sidebar_dark"], pady=12, padx=16)
        status_f.pack(side="bottom", fill="x")
        self.spinner_var = tk.StringVar(value="●")
        tk.Label(status_f, textvariable=self.spinner_var, font=("Segoe UI", 11),
                 fg=C["green"], bg=C["sidebar_dark"]).pack(side="left")
        self.status_var = tk.StringVar(value="Démarrage…")
        tk.Label(status_f, textvariable=self.status_var, font=("Segoe UI", 8),
                 fg="#8BAAD4", bg=C["sidebar_dark"], wraplength=180, justify="left"
        ).pack(side="left", padx=6)

    def _env_btn(self, parent, label: str, color: str, env: str) -> tk.Button:
        btn = tk.Button(parent, text=f"  ● {label}",
                        font=("Segoe UI", 10, "bold"), fg=C["text3"], bg=C["sidebar_item"],
                        activeforeground=color, activebackground=C["sidebar_item"],
                        relief="flat", bd=0, cursor="hand2", anchor="w",
                        padx=10, pady=8, command=lambda: self._switch_env(env))
        btn.bind("<Enter>", lambda e: btn.configure(fg=color))
        btn.bind("<Leave>", lambda _: self._refresh_env_btns())
        return btn

    def _perm_radio(self, parent, perm: str) -> None:
        color = perm_color(perm)
        f     = tk.Frame(parent, bg=C["sidebar"])
        f.pack(fill="x", pady=1)
        ind = tk.Frame(f, bg=C["sidebar"], width=3)
        ind.pack(side="left", fill="y")
        self._perm_indicators[perm] = ind
        rb = tk.Radiobutton(f, text=f"  {perm_icon(perm)}  {perm.capitalize()}",
                             variable=self.perm_var, value=perm,
                             font=("Segoe UI", 10), fg="#AABBDD", bg=C["sidebar"],
                             activebackground=C["sidebar_item"], activeforeground=color,
                             selectcolor=C["sidebar"], relief="flat", cursor="hand2",
                             command=lambda p=perm, c=color: self._on_perm_pick(p, c))
        rb.pack(side="left", fill="x", expand=True, padx=4, pady=4)
        if perm == "view":
            ind.configure(bg=color)

    def _on_perm_pick(self, perm: str, color: str) -> None:
        for p, ind in self._perm_indicators.items():
            ind.configure(bg=color if p == perm else C["sidebar"])

    def _sb_btn(self, parent, text: str, color: str, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, font=("Segoe UI", 10, "bold"),
                        fg=color, bg=C["sidebar_item"],
                        activeforeground=C["text_light"], activebackground=color,
                        relief="flat", bd=0, cursor="hand2",
                        anchor="w", padx=12, pady=9, command=cmd)
        btn.bind("<Enter>", lambda e: btn.configure(bg=color, fg=C["text_light"]))
        btn.bind("<Leave>", lambda e: btn.configure(bg=C["sidebar_item"], fg=color))
        return btn

    def _ghost_btn(self, parent, text: str, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, font=("Segoe UI", 9),
                        fg="#6688AA", bg=C["sidebar"],
                        activeforeground=C["text_light"], activebackground=C["sidebar_item"],
                        relief="flat", bd=0, cursor="hand2",
                        anchor="w", padx=4, pady=5, command=cmd)
        btn.bind("<Enter>", lambda e: btn.configure(fg=C["text_light"], bg=C["sidebar_item"]))
        btn.bind("<Leave>", lambda e: btn.configure(fg="#6688AA", bg=C["sidebar"]))
        return btn

    def _refresh_env_btns(self) -> None:
        for btn, env, color in [(self.btn_prod,"PROD",C["prod"]), (self.btn_rec,"RECETTE",C["recette"])]:
            active = self.env == env
            btn.configure(fg=color if active else C["text3"],
                          bg=C["sidebar_dark"] if active else C["sidebar_item"])

    # ── MAIN ─────────────────────────────────────────────────────────────────

    def _build_main(self) -> None:
        main = tk.Frame(self, bg=C["bg"])
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1, minsize=280)
        main.columnconfigure(2, weight=2)
        main.rowconfigure(0, weight=1)

        self._build_users_col(main)
        tk.Frame(main, bg=C["border"], width=1).grid(row=0, column=1, sticky="ns")
        self._build_streams_col(main)

    # ── Colonne utilisateurs ──────────────────────────────────────────────────

    def _build_users_col(self, parent) -> None:
        col = tk.Frame(parent, bg=C["bg"])
        col.grid(row=0, column=0, sticky="nsew")
        col.rowconfigure(2, weight=1)
        col.columnconfigure(0, weight=1)

        self._section_hdr(col, "Utilisateurs", "Ctrl+clic = multi-sélection", 0)

        # Recherche
        sf = tk.Frame(col, bg=C["bg_white"], padx=14, pady=10)
        sf.grid(row=1, column=0, sticky="ew")
        sf.columnconfigure(1, weight=1)
        tk.Label(sf, text="🔍", font=("Segoe UI",11), fg=C["text3"],
                 bg=C["bg_white"]).grid(row=0,column=0,padx=(0,8))
        self.user_search_var = tk.StringVar()
        self.user_search_var.trace_add("write", self._filter_users)
        tk.Entry(sf, textvariable=self.user_search_var, font=FONT_LABEL,
                 bg=C["bg_white"], fg=C["text"], relief="flat", bd=0,
                 insertbackground=C["blue"]).grid(row=0,column=1,sticky="ew",ipady=2)
        tk.Frame(sf, bg=C["border"], height=1).grid(row=1,column=0,columnspan=2,sticky="ew",pady=(6,0))

        lw = tk.Frame(col, bg=C["bg_white"])
        lw.grid(row=2, column=0, sticky="nsew")
        lw.rowconfigure(0, weight=1); lw.columnconfigure(0, weight=1)
        self.user_lb = tk.Listbox(lw, selectmode=tk.MULTIPLE, bg=C["bg_white"], fg=C["text"],
                                   font=FONT_LABEL, selectbackground=C["blue_light"],
                                   selectforeground=C["blue"], activestyle="none",
                                   highlightthickness=0, relief="flat", bd=0,
                                   exportselection=False, cursor="hand2")
        self.user_lb.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(lw, command=self.user_lb.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.user_lb.configure(yscrollcommand=sb.set)
        self.user_lb.bind("<<ListboxSelect>>", self._on_users_sel)

        footer = tk.Frame(col, bg=C["bg_panel"], padx=14, pady=6)
        footer.grid(row=3, column=0, sticky="ew")
        self.user_sel_var = tk.StringVar(value="Aucun utilisateur sélectionné")
        tk.Label(footer, textvariable=self.user_sel_var, font=FONT_SMALL,
                 fg=C["text3"], bg=C["bg_panel"], anchor="w").pack(fill="x")

    # ── Colonne streams ───────────────────────────────────────────────────────

    def _build_streams_col(self, parent) -> None:
        col = tk.Frame(parent, bg=C["bg"])
        col.grid(row=0, column=2, sticky="nsew")
        col.columnconfigure(1, weight=1)
        col.rowconfigure(1, weight=3)
        col.rowconfigure(3, weight=1)

        self._section_hdr(col, "Streams", "Double-clic = voir les droits", 0, colspan=2)

        # Catégories
        cat_pnl = tk.Frame(col, bg=C["bg_white"], width=170)
        cat_pnl.grid(row=1, column=0, sticky="nsew")
        cat_pnl.pack_propagate(False)
        cat_pnl.rowconfigure(1, weight=1); cat_pnl.columnconfigure(0, weight=1)

        tk.Label(cat_pnl, text="CATÉGORIES", font=("Segoe UI",8,"bold"),
                 fg=C["text3"], bg=C["bg_panel"], anchor="w",
                 padx=14, pady=10).pack(fill="x")
        tk.Frame(cat_pnl, bg=C["border"], height=1).pack(fill="x")

        lb_c = tk.Frame(cat_pnl, bg=C["bg_white"])
        lb_c.pack(fill="both", expand=True)
        lb_c.rowconfigure(0, weight=1); lb_c.columnconfigure(0, weight=1)
        self.cat_lb = tk.Listbox(lb_c, selectmode=tk.MULTIPLE, bg=C["bg_white"],
                                  fg=C["text"], font=FONT_BOLD,
                                  selectbackground=C["green_light"],
                                  selectforeground=C["green_dark"],
                                  activestyle="none", highlightthickness=0,
                                  relief="flat", bd=0, exportselection=False,
                                  cursor="hand2", width=16)
        self.cat_lb.grid(row=0, column=0, sticky="nsew")
        sb_c = ttk.Scrollbar(lb_c, command=self.cat_lb.yview)
        sb_c.grid(row=0, column=1, sticky="ns")
        self.cat_lb.configure(yscrollcommand=sb_c.set)
        self.cat_lb.bind("<<ListboxSelect>>", self._on_cat_sel)

        tk.Frame(cat_pnl, bg=C["border"], height=1).pack(fill="x")
        cb = tk.Frame(cat_pnl, bg=C["bg_panel"], pady=6)
        cb.pack(fill="x")
        self._link_btn(cb, "✓ Tout", self._sel_all_cats).pack(side="left", padx=8)
        self._link_btn(cb, "✗ Tout", self._desel_cats).pack(side="left")

        # Séparateur
        tk.Frame(col, bg=C["border"], width=1).grid(row=1, column=0, sticky="ns", padx=(170,0))

        # Streams
        stream_pnl = tk.Frame(col, bg=C["bg_white"])
        stream_pnl.grid(row=1, column=1, sticky="nsew")
        stream_pnl.rowconfigure(1, weight=1); stream_pnl.columnconfigure(0, weight=1)

        sf = tk.Frame(stream_pnl, bg=C["bg_white"], padx=14, pady=10)
        sf.grid(row=0, column=0, columnspan=2, sticky="ew")
        sf.columnconfigure(1, weight=1)
        tk.Label(sf, text="🔍", font=("Segoe UI",11), fg=C["text3"],
                 bg=C["bg_white"]).grid(row=0,column=0,padx=(0,8))
        self.stream_search_var = tk.StringVar()
        self.stream_search_var.trace_add("write", self._filter_streams)
        tk.Entry(sf, textvariable=self.stream_search_var, font=FONT_LABEL,
                 bg=C["bg_white"], fg=C["text"], relief="flat", bd=0,
                 insertbackground=C["blue"]).grid(row=0,column=1,sticky="ew",ipady=2)
        tk.Frame(sf, bg=C["border"], height=1).grid(row=1,column=0,columnspan=2,sticky="ew",pady=(6,0))

        lf = tk.Frame(stream_pnl, bg=C["bg_white"])
        lf.grid(row=1, column=0, sticky="nsew")
        lf.rowconfigure(0, weight=1); lf.columnconfigure(0, weight=1)
        self.stream_lb = tk.Listbox(lf, selectmode=tk.MULTIPLE, bg=C["bg_white"], fg=C["text"],
                                     font=FONT_LABEL, selectbackground=C["blue_light"],
                                     selectforeground=C["blue"], activestyle="none",
                                     highlightthickness=0, relief="flat", bd=0,
                                     exportselection=False, cursor="hand2")
        self.stream_lb.grid(row=0, column=0, sticky="nsew")
        sb_s = ttk.Scrollbar(lf, command=self.stream_lb.yview)
        sb_s.grid(row=0, column=1, sticky="ns")
        self.stream_lb.configure(yscrollcommand=sb_s.set)
        self.stream_lb.bind("<Double-Button-1>", self._on_stream_dbl)
        self.stream_lb.bind("<<ListboxSelect>>", self._on_stream_sel)
        Tooltip(self.stream_lb, "Double-clic pour voir les droits sur ce stream")

        tk.Frame(stream_pnl, bg=C["border"], height=1).grid(row=2,column=0,columnspan=2,sticky="ew")
        sf2 = tk.Frame(stream_pnl, bg=C["bg_panel"], pady=6, padx=12)
        sf2.grid(row=3, column=0, columnspan=2, sticky="ew")
        self._link_btn(sf2, "Tout sélectionner",   self._sel_all_streams).pack(side="left")
        tk.Label(sf2, text=" · ", fg=C["text3"], bg=C["bg_panel"],
                 font=FONT_SMALL).pack(side="left")
        self._link_btn(sf2, "Tout désélectionner", self._desel_streams).pack(side="left")
        self.stream_count_lbl = tk.Label(sf2, text="", font=FONT_SMALL,
                                          fg=C["green_dark"], bg=C["bg_panel"])
        self.stream_count_lbl.pack(side="right")

        # Séparateur
        tk.Frame(col, bg=C["border"], height=1).grid(row=2,column=0,columnspan=2,sticky="ew")

        # Journal
        log_pnl = tk.Frame(col, bg=C["bg_white"])
        log_pnl.grid(row=3, column=0, columnspan=2, sticky="nsew")
        log_pnl.rowconfigure(1, weight=1); log_pnl.columnconfigure(0, weight=1)

        lh = tk.Frame(log_pnl, bg=C["bg_panel"])
        lh.grid(row=0, column=0, sticky="ew")
        tk.Label(lh, text="Journal d'activité", font=FONT_BOLD,
                 fg=C["text2"], bg=C["bg_panel"], padx=14, pady=8).pack(side="left")
        self._link_btn(lh, "Effacer", self._clear_log).pack(side="right", padx=12)

        lf2 = tk.Frame(log_pnl, bg=C["bg_white"])
        lf2.grid(row=1, column=0, sticky="nsew")
        lf2.rowconfigure(0, weight=1); lf2.columnconfigure(0, weight=1)
        self.log_box = tk.Text(lf2, state="disabled", wrap="word",
                                bg=C["bg_white"], fg=C["text2"], font=FONT_MONO,
                                relief="flat", bd=0, padx=14, pady=8, cursor="arrow")
        self.log_box.grid(row=0, column=0, sticky="nsew")
        sb_l = ttk.Scrollbar(lf2, command=self.log_box.yview)
        sb_l.grid(row=0, column=1, sticky="ns")
        self.log_box.configure(yscrollcommand=sb_l.set)
        self.log_box.tag_config("ok",   foreground=C["success"],  font=("Consolas",9,"bold"))
        self.log_box.tag_config("err",  foreground=C["error"],    font=("Consolas",9,"bold"))
        self.log_box.tag_config("warn", foreground=C["warning"],  font=("Consolas",9,"bold"))
        self.log_box.tag_config("info", foreground=C["blue_mid"], font=("Consolas",9))
        self.log_box.tag_config("skip", foreground=C["text3"],    font=("Consolas",9))
        self.log_box.tag_config("head", foreground=C["blue"],     font=("Consolas",9,"bold"))
        self.log_box.tag_config("ts",   foreground=C["text3"],    font=("Consolas",9))

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _section_hdr(self, parent, title: str, sub: str, row: int, colspan: int = 1) -> None:
        f = tk.Frame(parent, bg=C["bg_white"])
        f.grid(row=row, column=0, columnspan=colspan, sticky="ew")
        inner = tk.Frame(f, bg=C["bg_white"], padx=16, pady=14)
        inner.pack(fill="x")
        tk.Label(inner, text=title, font=FONT_HEADER, fg=C["text"], bg=C["bg_white"]).pack(side="left")
        if sub:
            tk.Label(inner, text=f"  —  {sub}", font=FONT_SMALL,
                     fg=C["text3"], bg=C["bg_white"]).pack(side="left")
        tk.Frame(f, bg=C["border"], height=1).pack(fill="x")

    def _link_btn(self, parent, text: str, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, font=FONT_SMALL, fg=C["blue_mid"],
                        bg=parent.cget("bg"),
                        activeforeground=C["green_dark"], activebackground=parent.cget("bg"),
                        relief="flat", bd=0, cursor="hand2", command=cmd)
        btn.bind("<Enter>", lambda e: btn.configure(fg=C["green_dark"]))
        btn.bind("<Leave>", lambda e: btn.configure(fg=C["blue_mid"]))
        return btn

    # ── Environnement ─────────────────────────────────────────────────────────

    def _switch_env(self, env: str) -> None:
        if self.env == env: return
        self.env = env
        url = GRAYLOG_URL_PROD if env == "PROD" else GRAYLOG_URL_RECETTE
        self.client = GraylogClient(url, self.client.username,
                                     self.client.session.headers["Authorization"].split(" ")[1])
        # Reconstruire les headers avec les bons credentials décodés
        old_auth = self.client.session.headers.get("Authorization","")
        # On reconstruit simplement le client avec les mêmes creds
        b64 = old_auth.replace("Basic ","")
        decoded = base64.b64decode(b64).decode()
        username, password = decoded.split(":", 1)
        self.client = GraylogClient(url, username, password)

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
        self._log(f"✗  Erreur : {msg}", "err")
        self._set_status("Erreur de connexion")

    # ── Rebuild ───────────────────────────────────────────────────────────────

    def _rebuild_users(self, users: List) -> None:
        self.user_lb.delete(0, tk.END)
        self._user_id_map = {}
        for i, u in enumerate(sorted(users, key=lambda x: x["username"].lower())):
            label = f"  {u['username']}" + (f"  ({u['full_name']})" if u["full_name"] else "")
            self.user_lb.insert(tk.END, label)
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
            self.user_sel_var.set(f"{n} sélectionné(s) : {', '.join(names[:3])}{'…' if n>3 else ''}")
        else:
            self.user_sel_var.set("Aucun utilisateur sélectionné")
        for uid in self.sel_user_ids:
            if uid not in self.perms_cache:
                threading.Thread(
                    target=lambda u=uid: self.perms_cache.update({u: self.client.get_user_permissions(u)}),
                    daemon=True).start()

    def _on_stream_dbl(self, event) -> None:
        idx = self.stream_lb.nearest(event.y)
        if idx < 0 or idx not in self.stream_id_map: return
        StreamDetailWindow(self, self.stream_lb.get(idx).strip(),
                           self.stream_id_map[idx], self.client, self.users)

    # ── Guards ────────────────────────────────────────────────────────────────

    def _guard(self) -> bool:
        if not self.sel_user_ids:
            messagebox.showwarning("Sélection manquante",
                                   "Sélectionnez au moins un utilisateur.", parent=self)
            return False
        if not self.stream_lb.curselection():
            messagebox.showwarning("Sélection manquante",
                                   "Sélectionnez au moins un stream.", parent=self)
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
        self._log("── Inspection ──────────────────────────", "head")
        for uid in self.sel_user_ids:
            perms = self.perms_cache.get(uid, {})
            self._log(f"  👤 {self._uname(uid)}", "info")
            for sid, title in self._sel_streams():
                p = self.client.user_perm_on_stream(perms, sid)
                self._log(f"      {perm_icon(p) if p else '○'}  {title}  →  {p or 'aucune permission'}",
                          "ok" if p else "skip")

    def _apply_permissions(self) -> None:
        if not self._guard(): return
        cap = self.perm_var.get()
        nu  = len(self.sel_user_ids)
        ns  = len(self.stream_lb.curselection())
        self._log(f"── Appliquer « {cap} »  {nu}u × {ns}s ──────────", "head")
        threading.Thread(target=self._run_apply, args=(cap,), daemon=True).start()

    def _run_apply(self, cap: str) -> None:
        ok = skip = err = 0
        streams = self._sel_streams()
        total   = len(self.sel_user_ids) * len(streams)
        done    = 0

        for uid in self.sel_user_ids:
            uname = self._uname(uid)
            perms = self.perms_cache.get(uid, {})
            for sid, title in streams:
                if self.client.user_perm_on_stream(perms, sid) == cap:
                    self.after(0, self._log, f"  ⊘  [{uname}] {title}", "skip")
                    skip += 1
                else:
                    s, msg = self.client.set_permission(sid, uid, cap)
                    if s:
                        self.after(0, self._log, f"  ✓  [{uname}] {title}", "ok"); ok += 1
                    else:
                        self.after(0, self._log, f"  ✗  [{uname}] {title}  —  {msg}", "err"); err += 1
                done += 1
                self.after(0, self._set_progress, done / total,
                           f"{done}/{total} traités…")
            if ok: self.perms_cache[uid] = self.client.get_user_permissions(uid)

        log_to_file(self.client.username, self.env, "APPLY",
                    f"cap={cap} | {ok} ok, {skip} skip, {err} err")
        r = f"{ok} appliquées · {skip} ignorées · {err} erreurs"
        self.after(0, self._log, f"  → {r}", "ok" if not err else "warn")
        self.after(0, self._set_progress, 0.0, "")
        self.after(0, (messagebox.showinfo if not err else messagebox.showwarning), "Résultat", r)

    def _remove_permissions(self) -> None:
        if not self._guard(): return
        n = len(self.sel_user_ids) * len(self.stream_lb.curselection())
        if not messagebox.askyesno("Confirmer",
                                   f"Supprimer la permission pour {n} combinaison(s) ?",
                                   parent=self): return
        self._log("── Suppression ─────────────────────────", "head")
        threading.Thread(target=self._run_remove, daemon=True).start()

    def _run_remove(self) -> None:
        ok = err = 0
        streams = self._sel_streams()
        total   = len(self.sel_user_ids) * len(streams)
        done    = 0
        for uid in self.sel_user_ids:
            uname = self._uname(uid)
            for sid, title in streams:
                s, msg = self.client.remove_permission(sid, uid)
                if s:
                    self.after(0, self._log, f"  ✓  [{uname}] {title}", "ok"); ok += 1
                else:
                    self.after(0, self._log, f"  ✗  [{uname}] {title}  —  {msg}", "err"); err += 1
                done += 1
                self.after(0, self._set_progress, done / total, f"{done}/{total}…")
            if ok: self.perms_cache[uid] = self.client.get_user_permissions(uid)

        log_to_file(self.client.username, self.env, "REMOVE",
                    f"{ok} ok, {err} err")
        self.after(0, self._log, f"  → {ok} supprimées · {err} erreurs",
                   "ok" if not err else "warn")
        self.after(0, self._set_progress, 0.0, "")

    # ── Export CSV ────────────────────────────────────────────────────────────

    def _export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Tous", "*.*")],
            initialfile=f"graylog_permissions_{self.env}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            parent=self,
        )
        if not path: return
        self._log("── Export CSV ──────────────────────────", "head")
        threading.Thread(target=self._run_export, args=(path,), daemon=True).start()

    def _run_export(self, path: str) -> None:
        streams_sorted = sorted(self.streams.items(), key=lambda x: x[1].lower())
        users_sorted   = sorted(self.users,           key=lambda u: u["username"].lower())
        total          = len(users_sorted)

        rows: List[List[str]] = []
        for i, u in enumerate(users_sorted):
            perms = self.client.get_user_permissions(u["id"])
            row = [u["username"], u["full_name"]]
            for sid, _ in streams_sorted:
                cap = self.client.user_perm_on_stream(perms, sid)
                row.append(cap or "")
            rows.append(row)
            self.after(0, self._set_progress, (i+1)/total,
                       f"Export : {i+1}/{total} users…")

        header = ["username", "full_name"] + [t for _, t in streams_sorted]
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(header)
                w.writerows(rows)
            log_to_file(self.client.username, self.env, "EXPORT_CSV", path)
            self.after(0, self._log, f"  ✓  Export CSV : {path}", "ok")
        except Exception as e:
            self.after(0, self._log, f"  ✗  Erreur export : {e}", "err")
        self.after(0, self._set_progress, 0.0, "")

    # ── Outils ────────────────────────────────────────────────────────────────

    def _open_copy(self) -> None:
        CopyPermsWindow(self)

    def _open_compare(self) -> None:
        CompareWindow(self)

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

    # ── Status / Spinner / Progress ───────────────────────────────────────────

    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)

    def _set_progress(self, value: float, label: str) -> None:
        self.global_prog.set(value)
        self.prog_label.set(label)

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
    # Étape 1 : fenêtre de login
    login = LoginWindow()
    login.mainloop()

    client = login.result
    if client is None:
        return  # Fermé sans connexion ou non-admin

    # Étape 2 : application principale
    app = GraylogApp(client, login._initial_env)
    app.mainloop()


if __name__ == "__main__":
    main()
