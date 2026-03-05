# -*- coding: utf-8 -*-
"""Outil de gestion des permissions utilisateurs Graylog avec interface graphique."""

import base64
import logging
import re
import threading
from typing import Any, Dict, Optional, List, Tuple, Set
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import urllib3
import json
from urllib.parse import quote

try:
    from secret import GRAYLOG_URL, GRAYLOG_USERNAME, GRAYLOG_PASSWORD
except ImportError:
    raise SystemExit(
        "Fichier 'secret.py' introuvable. "
        "Créez-le avec GRAYLOG_URL, GRAYLOG_USERNAME et GRAYLOG_PASSWORD."
    )

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── Constantes ───────────────────────────────────────────────────────────────
PERMISSIONS:     List[str] = ["view", "manage", "own"]
WINDOW_SIZE:     str       = "1280x820"
GRN_PREFIX:      str       = "grn::::stream:"
GRN_USER_PREFIX: str       = "grn::::user:"
CATEGORY_RE                = re.compile(r"^\[([^\]]+)\]")   # "[AD] Mon stream" → "AD"


# ─── Client API ───────────────────────────────────────────────────────────────

class GraylogAPIError(Exception):
    """Erreur levée lors d'un appel à l'API Graylog."""


class GraylogClient:
    """Client pour l'API Graylog."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(self._default_headers())

    def _default_headers(self) -> Dict[str, str]:
        creds = f"{GRAYLOG_USERNAME}:{GRAYLOG_PASSWORD}"
        b64 = base64.b64encode(creds.encode()).decode()
        return {
            "Authorization": f"Basic {b64}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-By": "python-script",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        url = f"{GRAYLOG_URL.rstrip('/')}{path}"
        try:
            resp = self.session.request(method, url, timeout=15, **kwargs)
            resp.raise_for_status()
            if resp.status_code == 204 or not resp.content:
                return {}
            return resp.json()
        except requests.HTTPError as err:
            body = err.response.text[:500] if err.response is not None else ""
            logger.error("%s %s → HTTP %s: %s", method.upper(), url, err.response.status_code, body)
            return None
        except requests.RequestException as err:
            logger.error("%s %s → %s", method.upper(), url, err)
            return None

    # ── Données ────────────────────────────────────────────────────────────────

    def get_streams(self) -> Dict[str, str]:
        data = self._request("get", "/api/streams")
        if not data:
            return {}
        streams = {s["id"]: s.get("title", "Unknown") for s in data.get("streams", [])}
        logger.info("%d streams récupérés", len(streams))
        return streams

    def get_users(self) -> List[Dict[str, str]]:
        data = self._request("get", "/api/users")
        if not data:
            return []
        users = [
            {"id": u["id"], "username": u.get("username", ""), "full_name": u.get("full_name", "")}
            for u in data.get("users", [])
        ]
        logger.info("%d utilisateurs récupérés", len(users))
        return users

    def get_user_permissions(self, user_id: str) -> Dict[str, Any]:
        data = self._request("get", f"/api/authz/shares/user/{user_id}")
        return data if data is not None else {}

    def user_permission_on_stream(self, user_permissions: Dict[str, Any], stream_id: str) -> Optional[str]:
        context = user_permissions.get("context", {})
        return context.get("grantee_capabilities", {}).get(f"{GRN_PREFIX}{stream_id}")

    # ── Partages ───────────────────────────────────────────────────────────────

    def _get_stream_shares(self, stream_grn: str) -> Optional[Dict[str, Any]]:
        enc = quote(stream_grn, safe="")
        url = f"{GRAYLOG_URL.rstrip('/')}/api/authz/shares/entities/{enc}/prepare"
        try:
            resp = self.session.post(url, json={}, timeout=15)
            if resp.status_code in (200, 201):
                return resp.json()
            logger.error("prepare HTTP %s: %s", resp.status_code, resp.text[:300])
            return None
        except requests.RequestException as exc:
            logger.error("prepare exception: %s", exc)
            return None

    def _post_shares(self, stream_grn: str, grantees: Dict[str, str]) -> Tuple[bool, str]:
        enc = quote(stream_grn, safe="")
        url = f"{GRAYLOG_URL.rstrip('/')}/api/authz/shares/entities/{enc}"
        try:
            resp = self.session.post(url, json={"selected_grantee_capabilities": grantees}, timeout=15)
            if resp.status_code in (200, 201, 204):
                return True, "OK"
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
        except requests.RequestException as exc:
            return False, str(exc)

    def set_stream_permission(self, stream_id: str, user_id: str, capability: str = "view") -> Tuple[bool, str]:
        stream_grn = f"{GRN_PREFIX}{stream_id}"
        user_grn   = f"{GRN_USER_PREFIX}{user_id}"

        prepare = self._get_stream_shares(stream_grn)
        if prepare is None:
            return False, "Impossible de lire l'état actuel des partages (prepare)"

        existing: Dict[str, str] = prepare.get("selected_grantee_capabilities") or prepare.get("grantees") or {}
        updated  = dict(existing)
        updated[user_grn] = capability

        ok, msg = self._post_shares(stream_grn, updated)
        if ok:
            logger.info("Permission %s appliquée sur %s pour %s", capability, stream_id, user_id)
            return True, f"OK — {capability} appliqué"
        return False, msg

    def remove_stream_permission(self, stream_id: str, user_id: str) -> Tuple[bool, str]:
        stream_grn = f"{GRN_PREFIX}{stream_id}"
        user_grn   = f"{GRN_USER_PREFIX}{user_id}"

        prepare = self._get_stream_shares(stream_grn)
        if prepare is None:
            return False, "Impossible de lire l'état actuel des partages (prepare)"

        existing: Dict[str, str] = prepare.get("selected_grantee_capabilities") or prepare.get("grantees") or {}
        updated  = {k: v for k, v in existing.items() if k != user_grn}

        ok, msg = self._post_shares(stream_grn, updated)
        return (True, "Permission supprimée") if ok else (False, msg)


# ─── Utilitaires ──────────────────────────────────────────────────────────────

def extract_category(title: str) -> Optional[str]:
    """Extrait 'AD' depuis '[AD] Mon stream', ou None."""
    m = CATEGORY_RE.match(title.strip())
    return m.group(1).strip() if m else None


# ─── Interface graphique ───────────────────────────────────────────────────────

class GraylogPermissionManagerGUI:
    """Interface graphique pour gérer les permissions Graylog."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Graylog Permission Manager")
        self.root.geometry(WINDOW_SIZE)
        self.root.minsize(900, 650)

        self.client = GraylogClient()

        self.streams:           Dict[str, str]       = {}
        self.stream_id_map:     Dict[int, str]        = {}
        self.users:             List[Dict[str, str]]  = []
        self._user_id_map:      Dict[int, str]        = {}
        self.categories:        List[str]             = []
        self.selected_user_ids: List[str]             = []
        self.users_permissions: Dict[str, Dict[str, Any]] = {}

        self._build_ui()
        self._load_data_async()

    # ── Construction UI ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=2)
        main.rowconfigure(5, weight=1)

        # ── Statut ─────────────────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Connexion en cours…")
        ttk.Label(main, textvariable=self.status_var, foreground="gray").grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )

        # ── Utilisateurs (multi-sélection) ────────────────────────────────────
        user_frame = ttk.LabelFrame(main, text="Utilisateurs  (Ctrl+clic = multi-sélection)", padding=8)
        user_frame.grid(row=1, column=0, sticky="ew", pady=4)
        user_frame.columnconfigure(1, weight=1)

        ttk.Label(user_frame, text="Filtrer :").grid(row=0, column=0, padx=4, sticky="w")
        self.user_search_var = tk.StringVar()
        self.user_search_var.trace_add("write", self._filter_users)
        ttk.Entry(user_frame, textvariable=self.user_search_var).grid(row=0, column=1, sticky="ew", padx=4)

        ulf = ttk.Frame(user_frame)
        ulf.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        ulf.columnconfigure(0, weight=1)

        self.user_listbox = tk.Listbox(
            ulf, selectmode=tk.MULTIPLE, height=5,
            activestyle="dotbox", exportselection=False,
        )
        self.user_listbox.grid(row=0, column=0, sticky="ew")
        sb_u = ttk.Scrollbar(ulf, command=self.user_listbox.yview)
        sb_u.grid(row=0, column=1, sticky="ns")
        self.user_listbox.configure(yscrollcommand=sb_u.set)
        self.user_listbox.bind("<<ListboxSelect>>", self._on_users_selected)

        self.selected_users_label = ttk.Label(user_frame, text="Aucun utilisateur sélectionné", foreground="gray")
        self.selected_users_label.grid(row=2, column=0, columnspan=2, sticky="w", padx=4)

        # ── Catégories + Streams ───────────────────────────────────────────────
        streams_outer = ttk.LabelFrame(main, text="Streams", padding=8)
        streams_outer.grid(row=2, column=0, sticky="nsew", pady=4)
        streams_outer.columnconfigure(1, weight=1)
        streams_outer.rowconfigure(1, weight=1)

        # Catégories (colonne gauche)
        ttk.Label(streams_outer, text="Catégories", font=("", 9, "bold")).grid(
            row=0, column=0, sticky="w", padx=4
        )
        cat_frame = ttk.Frame(streams_outer)
        cat_frame.grid(row=1, column=0, sticky="ns", padx=(0, 10))
        cat_frame.rowconfigure(0, weight=1)

        self.cat_listbox = tk.Listbox(
            cat_frame, selectmode=tk.MULTIPLE, width=18,
            activestyle="dotbox", exportselection=False,
        )
        self.cat_listbox.grid(row=0, column=0, sticky="ns")
        sb_c = ttk.Scrollbar(cat_frame, command=self.cat_listbox.yview)
        sb_c.grid(row=0, column=1, sticky="ns")
        self.cat_listbox.configure(yscrollcommand=sb_c.set)
        self.cat_listbox.bind("<<ListboxSelect>>", self._on_category_selected)

        cat_btn = ttk.Frame(streams_outer)
        cat_btn.grid(row=2, column=0, sticky="w", pady=2)
        ttk.Button(cat_btn, text="Tout ✓", width=7, command=self._select_all_categories).pack(side=tk.LEFT, padx=1)
        ttk.Button(cat_btn, text="Tout ✗", width=7, command=self._deselect_all_categories).pack(side=tk.LEFT, padx=1)

        # Streams (colonne droite)
        right = ttk.Frame(streams_outer)
        right.grid(row=0, column=1, rowspan=3, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        sf = ttk.Frame(right)
        sf.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        sf.columnconfigure(1, weight=1)
        ttk.Label(sf, text="Filtrer :").grid(row=0, column=0, padx=4)
        self.stream_search_var = tk.StringVar()
        self.stream_search_var.trace_add("write", self._filter_streams)
        ttk.Entry(sf, textvariable=self.stream_search_var).grid(row=0, column=1, sticky="ew", padx=4)

        lf = ttk.Frame(right)
        lf.grid(row=1, column=0, sticky="nsew")
        lf.columnconfigure(0, weight=1)
        lf.rowconfigure(0, weight=1)

        self.streams_listbox = tk.Listbox(
            lf, selectmode=tk.MULTIPLE,
            activestyle="dotbox", exportselection=False,
        )
        self.streams_listbox.grid(row=0, column=0, sticky="nsew")
        sb_sy = ttk.Scrollbar(lf, command=self.streams_listbox.yview)
        sb_sy.grid(row=0, column=1, sticky="ns")
        sb_sx = ttk.Scrollbar(lf, orient=tk.HORIZONTAL, command=self.streams_listbox.xview)
        sb_sx.grid(row=1, column=0, sticky="ew")
        self.streams_listbox.configure(yscrollcommand=sb_sy.set, xscrollcommand=sb_sx.set)

        sel_btn = ttk.Frame(right)
        sel_btn.grid(row=2, column=0, sticky="w", pady=2)
        ttk.Button(sel_btn, text="Tout sélectionner",   command=self._select_all_streams).pack(side=tk.LEFT, padx=2)
        ttk.Button(sel_btn, text="Tout désélectionner", command=self._deselect_all_streams).pack(side=tk.LEFT, padx=2)

        # ── Permission ─────────────────────────────────────────────────────────
        perm_frame = ttk.LabelFrame(main, text="Permission à appliquer", padding=8)
        perm_frame.grid(row=3, column=0, sticky="ew", pady=4)
        self.perm_var = tk.StringVar(value="view")
        for perm in PERMISSIONS:
            ttk.Radiobutton(perm_frame, text=perm.capitalize(),
                            variable=self.perm_var, value=perm).pack(side=tk.LEFT, padx=12)

        # ── Actions ────────────────────────────────────────────────────────────
        af = ttk.Frame(main)
        af.grid(row=4, column=0, sticky="ew", pady=6)
        ttk.Button(af, text="🔍  Permissions actuelles", command=self._show_current_permissions).pack(side=tk.LEFT, padx=4)
        ttk.Button(af, text="✅  Appliquer",             command=self._apply_permissions).pack(side=tk.LEFT, padx=4)
        ttk.Button(af, text="🗑  Supprimer",             command=self._remove_permissions).pack(side=tk.LEFT, padx=4)
        ttk.Button(af, text="🔄  Rafraîchir",            command=self._load_data_async).pack(side=tk.RIGHT, padx=4)

        # ── Logs ───────────────────────────────────────────────────────────────
        log_frame = ttk.LabelFrame(main, text="Logs", padding=8)
        log_frame.grid(row=5, column=0, sticky="nsew", pady=4)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, height=8, state="disabled", wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        sb_log = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        sb_log.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=sb_log.set)
        self.log_text.tag_config("ok",   foreground="#2a9d2a")
        self.log_text.tag_config("err",  foreground="#cc3333")
        self.log_text.tag_config("info", foreground="#1a6fcc")
        self.log_text.tag_config("skip", foreground="#888888")

        ttk.Button(log_frame, text="Effacer", command=self._clear_logs).grid(
            row=1, column=0, sticky="e", pady=(4, 0)
        )

    # ── Chargement ─────────────────────────────────────────────────────────────

    def _load_data_async(self) -> None:
        self._set_status("Chargement…")
        self._log("Chargement des données depuis Graylog…", "info")
        threading.Thread(target=self._load_data, daemon=True).start()

    def _load_data(self) -> None:
        try:
            streams = self.client.get_streams()
            users   = self.client.get_users()
            self.root.after(0, self._populate_data, streams, users)
        except Exception as exc:
            self.root.after(0, self._on_load_error, str(exc))

    def _populate_data(self, streams: Dict[str, str], users: List[Dict[str, str]]) -> None:
        self.streams = streams
        self.users   = users
        self.users_permissions.clear()
        self.selected_user_ids.clear()

        self._rebuild_user_list(users)
        self._rebuild_categories(streams)
        self._rebuild_stream_list(streams)

        self._log(f"✓ {len(self.streams)} streams chargés", "ok")
        self._log(f"✓ {len(self.users)} utilisateurs chargés", "ok")
        self._set_status(f"Connecté — {len(self.streams)} streams, {len(self.users)} utilisateurs")

    def _on_load_error(self, msg: str) -> None:
        self._log(f"✗ Erreur de chargement : {msg}", "err")
        self._set_status("Erreur de connexion")
        messagebox.showerror("Erreur", f"Impossible de charger les données :\n{msg}")

    # ── Rebuild widgets ────────────────────────────────────────────────────────

    def _rebuild_user_list(self, users: List[Dict[str, str]]) -> None:
        self.user_listbox.delete(0, tk.END)
        self._user_id_map = {}
        for idx, u in enumerate(sorted(users, key=lambda x: x["username"].lower())):
            self.user_listbox.insert(tk.END, f"{u['username']}  —  {u['full_name']}")
            self._user_id_map[idx] = u["id"]

    def _rebuild_categories(self, streams: Dict[str, str]) -> None:
        cats: Set[str] = set()
        for title in streams.values():
            cat = extract_category(title)
            if cat:
                cats.add(cat)
        self.categories = sorted(cats, key=str.lower)
        self.cat_listbox.delete(0, tk.END)
        for cat in self.categories:
            self.cat_listbox.insert(tk.END, f"[{cat}]")

    def _rebuild_stream_list(self, streams: Dict[str, str]) -> None:
        self.streams_listbox.delete(0, tk.END)
        self.stream_id_map.clear()
        for idx, (sid, title) in enumerate(sorted(streams.items(), key=lambda x: x[1].lower())):
            self.streams_listbox.insert(tk.END, title)
            self.stream_id_map[idx] = sid

    # ── Filtres ────────────────────────────────────────────────────────────────

    def _filter_users(self, *_) -> None:
        query = self.user_search_var.get().lower()
        filtered = [u for u in self.users
                    if query in u["username"].lower() or query in u["full_name"].lower()]
        self._rebuild_user_list(filtered)

    def _filter_streams(self, *_) -> None:
        query = self.stream_search_var.get().lower()
        filtered = {sid: t for sid, t in self.streams.items() if query in t.lower()}
        self._rebuild_stream_list(filtered)

    # ── Sélection catégories → streams ────────────────────────────────────────

    def _on_category_selected(self, _event=None) -> None:
        selected_cats: Set[str] = {self.categories[i] for i in self.cat_listbox.curselection()}
        if not selected_cats:
            return
        self.streams_listbox.selection_clear(0, tk.END)
        for i in range(self.streams_listbox.size()):
            if extract_category(self.streams_listbox.get(i)) in selected_cats:
                self.streams_listbox.selection_set(i)
        count = len(self.streams_listbox.curselection())
        self._log(f"Catégorie(s) {sorted(selected_cats)} → {count} stream(s) sélectionné(s)", "info")

    def _select_all_categories(self) -> None:
        self.cat_listbox.select_set(0, tk.END)
        self._on_category_selected()

    def _deselect_all_categories(self) -> None:
        self.cat_listbox.selection_clear(0, tk.END)

    # ── Sélection utilisateurs ─────────────────────────────────────────────────

    def _on_users_selected(self, _event=None) -> None:
        self.selected_user_ids = [self._user_id_map[i] for i in self.user_listbox.curselection()]
        names = [self.user_listbox.get(i).split("—")[0].strip() for i in self.user_listbox.curselection()]
        if names:
            self.selected_users_label.configure(
                text=f"{len(names)} sélectionné(s) : {', '.join(names)}",
                foreground="black",
            )
        else:
            self.selected_users_label.configure(text="Aucun utilisateur sélectionné", foreground="gray")

        for uid in self.selected_user_ids:
            if uid not in self.users_permissions:
                threading.Thread(target=self._fetch_user_permissions, args=(uid,), daemon=True).start()

    def _fetch_user_permissions(self, user_id: str) -> None:
        self.users_permissions[user_id] = self.client.get_user_permissions(user_id)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _select_all_streams(self) -> None:
        self.streams_listbox.select_set(0, tk.END)

    def _deselect_all_streams(self) -> None:
        self.streams_listbox.selection_clear(0, tk.END)

    def _get_selected_streams(self) -> List[Tuple[str, str]]:
        return [(self.stream_id_map[i], self.streams_listbox.get(i))
                for i in self.streams_listbox.curselection()]

    def _guard_selection(self) -> bool:
        if not self.selected_user_ids:
            messagebox.showwarning("Attention", "Veuillez sélectionner au moins un utilisateur.")
            return False
        if not self.streams_listbox.curselection():
            messagebox.showwarning("Attention", "Veuillez sélectionner au moins un stream.")
            return False
        return True

    def _username_for(self, user_id: str) -> str:
        return next((u["username"] for u in self.users if u["id"] == user_id), user_id)

    # ── Actions ────────────────────────────────────────────────────────────────

    def _show_current_permissions(self) -> None:
        if not self._guard_selection():
            return
        self._log("\n── Permissions actuelles ──", "info")
        for uid in self.selected_user_ids:
            perms = self.users_permissions.get(uid, {})
            self._log(f"  👤 {self._username_for(uid)}", "info")
            for stream_id, title in self._get_selected_streams():
                perm = self.client.user_permission_on_stream(perms, stream_id)
                if perm:
                    self._log(f"      • {title}: {perm}", "ok")
                else:
                    self._log(f"      • {title}: aucune permission", "skip")

    def _apply_permissions(self) -> None:
        if not self._guard_selection():
            return
        capability = self.perm_var.get()
        n_u = len(self.selected_user_ids)
        n_s = len(self.streams_listbox.curselection())
        self._log(f"\n── Application « {capability} » → {n_u} user(s) × {n_s} stream(s) ──", "info")
        threading.Thread(target=self._run_apply, args=(capability,), daemon=True).start()

    def _run_apply(self, capability: str) -> None:
        total_ok = total_skip = total_err = 0
        streams = self._get_selected_streams()

        for uid in self.selected_user_ids:
            uname = self._username_for(uid)
            perms = self.users_permissions.get(uid, {})
            ok = skip = err = 0
            for stream_id, title in streams:
                if self.client.user_permission_on_stream(perms, stream_id) == capability:
                    self.root.after(0, self._log, f"  ⊘ [{uname}] {title}: déjà « {capability} »", "skip")
                    skip += 1
                    continue
                success, msg = self.client.set_stream_permission(stream_id, uid, capability)
                if success:
                    self.root.after(0, self._log, f"  ✓ [{uname}] {title}: {capability} appliqué", "ok")
                    ok += 1
                else:
                    self.root.after(0, self._log, f"  ✗ [{uname}] {title}: {msg}", "err")
                    err += 1
            if ok:
                self.users_permissions[uid] = self.client.get_user_permissions(uid)
            total_ok += ok; total_skip += skip; total_err += err

        summary = f"\nRésumé : {total_ok} appliquées, {total_skip} ignorées, {total_err} erreurs"
        self.root.after(0, self._log, summary, "info")
        self.root.after(
            0,
            messagebox.showinfo if not total_err else messagebox.showwarning,
            "Résultat", summary.strip(),
        )

    def _remove_permissions(self) -> None:
        if not self._guard_selection():
            return
        n = len(self.selected_user_ids) * len(self.streams_listbox.curselection())
        if not messagebox.askyesno("Confirmation", f"Supprimer la permission pour {n} combinaison(s) ?"):
            return
        self._log("\n── Suppression des permissions ──", "info")
        threading.Thread(target=self._run_remove, daemon=True).start()

    def _run_remove(self) -> None:
        total_ok = total_err = 0
        streams = self._get_selected_streams()
        for uid in self.selected_user_ids:
            uname = self._username_for(uid)
            ok = err = 0
            for stream_id, title in streams:
                success, msg = self.client.remove_stream_permission(stream_id, uid)
                if success:
                    self.root.after(0, self._log, f"  ✓ [{uname}] {title}: supprimée", "ok")
                    ok += 1
                else:
                    self.root.after(0, self._log, f"  ✗ [{uname}] {title}: {msg}", "err")
                    err += 1
            if ok:
                self.users_permissions[uid] = self.client.get_user_permissions(uid)
            total_ok += ok; total_err += err
        self.root.after(0, self._log, f"\nRésumé : {total_ok} supprimées, {total_err} erreurs", "info")

    # ── Logs ───────────────────────────────────────────────────────────────────

    def _log(self, message: str, tag: str = "") -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _clear_logs(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)


# ─── Point d'entrée ───────────────────────────────────────────────────────────

def main() -> None:
    root = tk.Tk()
    GraylogPermissionManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
