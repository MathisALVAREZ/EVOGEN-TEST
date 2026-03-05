# -*- coding: utf-8 -*-

“”“Outil de gestion des permissions utilisateurs Graylog avec interface graphique.”””

import base64
import logging
import threading
from typing import Any, Dict, Optional, List, Tuple
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
“Fichier ‘secret.py’ introuvable. “
“Créez-le avec GRAYLOG_URL, GRAYLOG_USERNAME et GRAYLOG_PASSWORD.”
)

# Désactiver les avertissements SSL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format=”[%(levelname)s] %(message)s”)
logger = logging.getLogger(**name**)

# ─── Constantes ──────────────────────────────────────────────────────────────

PERMISSIONS: List[str] = [“view”, “manage”, “own”]
WINDOW_SIZE: str = “1100x750”
GRN_PREFIX: str = “grn::::stream:”
GRN_USER_PREFIX: str = “grn::::user:”

# ─── Client API ──────────────────────────────────────────────────────────────

class GraylogAPIError(Exception):
“”“Erreur levée lors d’un appel à l’API Graylog.”””

class GraylogClient:
“”“Client pour l’API Graylog.”””

```
def __init__(self) -> None:
    self.session = requests.Session()
    self.session.verify = False
    self.session.headers.update(self._default_headers())

# ── Helpers ──────────────────────────────────────────────────────────────

def _default_headers(self) -> Dict[str, str]:
    creds = f"{GRAYLOG_USERNAME}:{GRAYLOG_PASSWORD}"
    b64 = base64.b64encode(creds.encode()).decode()
    return {
        "Authorization": f"Basic {b64}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Requested-By": "python-script",
    }

def _request(
    self,
    method: str,
    path: str,
    raise_on_error: bool = False,
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    url = f"{GRAYLOG_URL.rstrip('/')}{path}"
    try:
        resp = self.session.request(method, url, timeout=15, **kwargs)
        resp.raise_for_status()
        # Certains endpoints retournent 204 sans corps
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()
    except requests.HTTPError as err:
        body = err.response.text[:500] if err.response is not None else ""
        msg = f"{method.upper()} {url} → HTTP {err.response.status_code}: {body}"
        logger.error(msg)
        if raise_on_error:
            raise GraylogAPIError(msg) from err
        return None
    except requests.RequestException as err:
        msg = f"{method.upper()} {url} → {err}"
        logger.error(msg)
        if raise_on_error:
            raise GraylogAPIError(msg) from err
        return None

# ── Méthodes publiques ────────────────────────────────────────────────────

def get_streams(self) -> Dict[str, str]:
    """Retourne {stream_id: titre}."""
    data = self._request("get", "/api/streams")
    if not data:
        return {}
    streams = {s["id"]: s.get("title", "Unknown") for s in data.get("streams", [])}
    logger.info("%d streams récupérés", len(streams))
    return streams

def get_users(self) -> List[Dict[str, str]]:
    """Retourne une liste de dicts {id, username, full_name}."""
    data = self._request("get", "/api/users")
    if not data:
        return []
    users = [
        {
            "id": u["id"],
            "username": u.get("username", ""),
            "full_name": u.get("full_name", ""),
        }
        for u in data.get("users", [])
    ]
    logger.info("%d utilisateurs récupérés", len(users))
    return users

def get_user_permissions(self, user_id: str) -> Dict[str, Any]:
    """Récupère toutes les permissions d'un utilisateur."""
    data = self._request("get", f"/api/authz/shares/user/{user_id}")
    if data is not None:
        logger.info("Permissions récupérées pour %s", user_id)
        return data
    logger.error("Impossible de récupérer les permissions pour %s", user_id)
    return {}

def user_permission_on_stream(
    self, user_permissions: Dict[str, Any], stream_id: str
) -> Optional[str]:
    """Retourne la capability de l'utilisateur sur le stream, ou None."""
    context = user_permissions.get("context", {})
    grantee_capabilities = context.get("grantee_capabilities", {})
    return grantee_capabilities.get(f"{GRN_PREFIX}{stream_id}")

def _get_stream_shares(self, stream_grn: str) -> Optional[Dict[str, Any]]:
    """
    Récupère l'état actuel des partages d'un stream via POST .../prepare.
    Retourne le dict complet ou None en cas d'erreur.
    """
    stream_grn_enc = quote(stream_grn, safe="")
    url = f"{GRAYLOG_URL.rstrip('/')}/api/authz/shares/entities/{stream_grn_enc}/prepare"
    try:
        resp = self.session.post(url, json={}, timeout=15)
        logger.info("POST prepare → HTTP %s", resp.status_code)
        if resp.status_code in (200, 201):
            return resp.json()
        logger.error("prepare HTTP %s: %s", resp.status_code, resp.text[:300])
        return None
    except requests.RequestException as exc:
        logger.error("prepare exception: %s", exc)
        return None

def set_stream_permission(
    self, stream_id: str, user_id: str, capability: str = "view"
) -> Tuple[bool, str]:
    """
    Définit la permission d'un utilisateur sur un stream.

    Stratégie correcte pour l'API Graylog ≥ 4.x :
      1. POST /api/authz/shares/entities/{stream_GRN}/prepare  → obtenir l'état actuel
      2. POST /api/authz/shares/entities/{stream_GRN}          → envoyer la liste complète
         des grantees (existants + nouveau/modifié).
    """
    stream_grn     = f"{GRN_PREFIX}{stream_id}"
    user_grn       = f"{GRN_USER_PREFIX}{user_id}"
    stream_grn_enc = quote(stream_grn, safe="")

    # ── 1. Récupérer l'état actuel des partages ──────────────────────────
    prepare = self._get_stream_shares(stream_grn)
    if prepare is None:
        return False, "Impossible de lire l'état actuel des partages (prepare)"

    # ── 2. Construire la liste des grantees ───────────────────────────────
    # Le champ peut s'appeler "selected_grantee_capabilities" ou "grantees"
    # selon la version de Graylog. On teste les deux.
    existing: Dict[str, str] = (
        prepare.get("selected_grantee_capabilities")
        or prepare.get("grantees")
        or {}
    )

    # Fusionner : on écrase/ajoute la permission pour cet utilisateur
    updated = dict(existing)
    updated[user_grn] = capability

    payload = {"selected_grantee_capabilities": updated}

    url = f"{GRAYLOG_URL.rstrip('/')}/api/authz/shares/entities/{stream_grn_enc}"
    logger.info("POST %s — %d grantees", url, len(updated))
    logger.debug("Payload: %s", json.dumps(payload))

    try:
        resp = self.session.post(url, json=payload, timeout=15)
        if resp.status_code in (200, 201, 204):
            logger.info("Permission %s appliquée sur %s pour %s", capability, stream_id, user_id)
            return True, f"OK — {capability} appliqué"
        msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
        logger.error(msg)
        return False, msg
    except requests.RequestException as exc:
        msg = str(exc)
        logger.error("Erreur POST shares: %s", msg)
        return False, msg

def remove_stream_permission(self, stream_id: str, user_id: str) -> Tuple[bool, str]:
    """
    Supprime la permission d'un utilisateur sur un stream.
    Même logique que set_stream_permission mais en retirant le grantee.
    """
    stream_grn     = f"{GRN_PREFIX}{stream_id}"
    user_grn       = f"{GRN_USER_PREFIX}{user_id}"
    stream_grn_enc = quote(stream_grn, safe="")

    prepare = self._get_stream_shares(stream_grn)
    if prepare is None:
        return False, "Impossible de lire l'état actuel des partages (prepare)"

    existing: Dict[str, str] = (
        prepare.get("selected_grantee_capabilities")
        or prepare.get("grantees")
        or {}
    )

    updated = {k: v for k, v in existing.items() if k != user_grn}
    payload = {"selected_grantee_capabilities": updated}

    url = f"{GRAYLOG_URL.rstrip('/')}/api/authz/shares/entities/{stream_grn_enc}"
    try:
        resp = self.session.post(url, json=payload, timeout=15)
        if resp.status_code in (200, 201, 204):
            return True, "Permission supprimée"
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
    except requests.RequestException as exc:
        return False, str(exc)
```

# ─── Interface graphique ──────────────────────────────────────────────────────

class GraylogPermissionManagerGUI:
“”“Interface graphique pour gérer les permissions Graylog.”””

```
def __init__(self, root: tk.Tk) -> None:
    self.root = root
    self.root.title("Graylog Permission Manager")
    self.root.geometry(WINDOW_SIZE)
    self.root.minsize(800, 600)

    self.client = GraylogClient()
    self.streams: Dict[str, str] = {}          # {stream_id: title}
    self.stream_id_map: Dict[int, str] = {}    # {listbox_index: stream_id}
    self.users: List[Dict[str, str]] = []
    self.selected_user_id: Optional[str] = None
    self.user_permissions: Dict[str, Any] = {}

    self._build_ui()
    self._load_data_async()

# ── Construction de l'UI ──────────────────────────────────────────────────

def _build_ui(self) -> None:
    self.root.columnconfigure(0, weight=1)
    self.root.rowconfigure(0, weight=1)

    main = ttk.Frame(self.root, padding=10)
    main.grid(row=0, column=0, sticky="nsew")
    main.columnconfigure(0, weight=1)
    main.rowconfigure(2, weight=2)  # zone streams extensible
    main.rowconfigure(5, weight=1)  # zone logs extensible

    # ── Barre de statut ──────────────────────────────────────────────────
    self.status_var = tk.StringVar(value="Connexion en cours…")
    ttk.Label(main, textvariable=self.status_var, foreground="gray").grid(
        row=0, column=0, sticky="w", pady=(0, 4)
    )

    # ── Sélection utilisateur ────────────────────────────────────────────
    user_frame = ttk.LabelFrame(main, text="Utilisateur", padding=8)
    user_frame.grid(row=1, column=0, sticky="ew", pady=4)
    user_frame.columnconfigure(1, weight=1)

    ttk.Label(user_frame, text="Rechercher :").grid(row=0, column=0, padx=4)
    self.user_search_var = tk.StringVar()
    self.user_search_var.trace_add("write", self._filter_users)
    ttk.Entry(user_frame, textvariable=self.user_search_var).grid(
        row=0, column=1, sticky="ew", padx=4
    )

    ttk.Label(user_frame, text="Utilisateur :").grid(row=1, column=0, padx=4, pady=4)
    self.user_var = tk.StringVar()
    self.user_combo = ttk.Combobox(
        user_frame, textvariable=self.user_var, state="readonly", width=50
    )
    self.user_combo.grid(row=1, column=1, sticky="ew", padx=4)
    self.user_combo.bind("<<ComboboxSelected>>", self._on_user_selected)

    # ── Liste des streams ────────────────────────────────────────────────
    streams_frame = ttk.LabelFrame(main, text="Streams (Ctrl+clic pour multi-sélection)", padding=8)
    streams_frame.grid(row=2, column=0, sticky="nsew", pady=4)
    streams_frame.columnconfigure(0, weight=1)
    streams_frame.rowconfigure(1, weight=1)

    # Recherche dans les streams
    stream_search_frame = ttk.Frame(streams_frame)
    stream_search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 4))
    stream_search_frame.columnconfigure(1, weight=1)
    ttk.Label(stream_search_frame, text="Filtrer :").grid(row=0, column=0, padx=4)
    self.stream_search_var = tk.StringVar()
    self.stream_search_var.trace_add("write", self._filter_streams)
    ttk.Entry(stream_search_frame, textvariable=self.stream_search_var).grid(
        row=0, column=1, sticky="ew", padx=4
    )

    list_frame = ttk.Frame(streams_frame)
    list_frame.grid(row=1, column=0, sticky="nsew")
    list_frame.columnconfigure(0, weight=1)
    list_frame.rowconfigure(0, weight=1)

    self.streams_listbox = tk.Listbox(
        list_frame, selectmode=tk.MULTIPLE, activestyle="dotbox"
    )
    self.streams_listbox.grid(row=0, column=0, sticky="nsew")

    sb_y = ttk.Scrollbar(list_frame, command=self.streams_listbox.yview)
    sb_y.grid(row=0, column=1, sticky="ns")
    sb_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.streams_listbox.xview)
    sb_x.grid(row=1, column=0, sticky="ew")
    self.streams_listbox.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)

    # Boutons de sélection rapide
    sel_frame = ttk.Frame(streams_frame)
    sel_frame.grid(row=2, column=0, sticky="w", pady=4)
    ttk.Button(sel_frame, text="Tout sélectionner", command=self._select_all_streams).pack(side=tk.LEFT, padx=2)
    ttk.Button(sel_frame, text="Tout désélectionner", command=self._deselect_all_streams).pack(side=tk.LEFT, padx=2)

    # ── Type de permission ───────────────────────────────────────────────
    perm_frame = ttk.LabelFrame(main, text="Permission à appliquer", padding=8)
    perm_frame.grid(row=3, column=0, sticky="ew", pady=4)

    self.perm_var = tk.StringVar(value="view")
    for perm in PERMISSIONS:
        ttk.Radiobutton(
            perm_frame, text=perm.capitalize(), variable=self.perm_var, value=perm
        ).pack(side=tk.LEFT, padx=12)

    # ── Boutons d'action ─────────────────────────────────────────────────
    action_frame = ttk.Frame(main)
    action_frame.grid(row=4, column=0, sticky="ew", pady=6)

    ttk.Button(
        action_frame,
        text="🔍  Permissions actuelles",
        command=self._show_current_permissions,
    ).pack(side=tk.LEFT, padx=4)
    ttk.Button(
        action_frame,
        text="✅  Appliquer",
        command=self._apply_permissions,
    ).pack(side=tk.LEFT, padx=4)
    ttk.Button(
        action_frame,
        text="🗑  Supprimer la permission",
        command=self._remove_permissions,
    ).pack(side=tk.LEFT, padx=4)
    ttk.Button(
        action_frame,
        text="🔄  Rafraîchir",
        command=self._load_data_async,
    ).pack(side=tk.RIGHT, padx=4)

    # ── Zone de logs ─────────────────────────────────────────────────────
    log_frame = ttk.LabelFrame(main, text="Logs", padding=8)
    log_frame.grid(row=5, column=0, sticky="nsew", pady=4)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(0, weight=1)

    self.log_text = tk.Text(log_frame, height=8, state="disabled", wrap="word")
    self.log_text.grid(row=0, column=0, sticky="nsew")
    sb_log = ttk.Scrollbar(log_frame, command=self.log_text.yview)
    sb_log.grid(row=0, column=1, sticky="ns")
    self.log_text.configure(yscrollcommand=sb_log.set)

    # Tags de couleur pour les logs
    self.log_text.tag_config("ok", foreground="#2a9d2a")
    self.log_text.tag_config("err", foreground="#cc3333")
    self.log_text.tag_config("info", foreground="#1a6fcc")
    self.log_text.tag_config("skip", foreground="#888888")

    ttk.Button(log_frame, text="Effacer les logs", command=self._clear_logs).grid(
        row=1, column=0, sticky="e", pady=(4, 0)
    )

# ── Chargement des données ────────────────────────────────────────────────

def _load_data_async(self) -> None:
    """Lance le chargement dans un thread séparé pour ne pas bloquer l'UI."""
    self._set_status("Chargement…")
    self._log("Chargement des données depuis Graylog…", tag="info")
    threading.Thread(target=self._load_data, daemon=True).start()

def _load_data(self) -> None:
    try:
        streams = self.client.get_streams()
        users = self.client.get_users()
        self.root.after(0, self._populate_data, streams, users)
    except Exception as exc:
        self.root.after(0, self._on_load_error, str(exc))

def _populate_data(self, streams: Dict[str, str], users: List[Dict[str, str]]) -> None:
    self.streams = streams
    self.users = users

    self._rebuild_stream_list(streams)
    self._rebuild_user_combo(users)

    self._log(f"✓ {len(self.streams)} streams chargés", tag="ok")
    self._log(f"✓ {len(self.users)} utilisateurs chargés", tag="ok")
    self._set_status(f"Connecté — {len(self.streams)} streams, {len(self.users)} utilisateurs")

def _on_load_error(self, msg: str) -> None:
    self._log(f"✗ Erreur de chargement: {msg}", tag="err")
    self._set_status("Erreur de connexion")
    messagebox.showerror("Erreur", f"Impossible de charger les données:\n{msg}")

def _rebuild_stream_list(self, streams: Dict[str, str]) -> None:
    self.streams_listbox.delete(0, tk.END)
    self.stream_id_map.clear()
    for idx, (sid, title) in enumerate(sorted(streams.items(), key=lambda x: x[1].lower())):
        self.streams_listbox.insert(tk.END, title)
        self.stream_id_map[idx] = sid

def _rebuild_user_combo(self, users: List[Dict[str, str]]) -> None:
    labels = [
        f"{u['username']}  —  {u['full_name']}  ({u['id']})"
        for u in sorted(users, key=lambda u: u["username"].lower())
    ]
    self.user_combo["values"] = labels

# ── Filtres ───────────────────────────────────────────────────────────────

def _filter_users(self, *_) -> None:
    query = self.user_search_var.get().lower()
    filtered = [
        u for u in self.users
        if query in u["username"].lower() or query in u["full_name"].lower()
    ]
    self._rebuild_user_combo(filtered)

def _filter_streams(self, *_) -> None:
    query = self.stream_search_var.get().lower()
    filtered = {sid: title for sid, title in self.streams.items() if query in title.lower()}
    self._rebuild_stream_list(filtered)

# ── Sélection utilisateur ─────────────────────────────────────────────────

def _on_user_selected(self, _event=None) -> None:
    raw = self.user_var.get()
    if not raw:
        return
    # Extraire l'ID entre les dernières parenthèses
    self.selected_user_id = raw.rsplit("(", 1)[-1].rstrip(")")
    self._log(f"Utilisateur sélectionné : {raw}", tag="info")
    threading.Thread(target=self._fetch_user_permissions, daemon=True).start()

def _fetch_user_permissions(self) -> None:
    if not self.selected_user_id:
        return
    perms = self.client.get_user_permissions(self.selected_user_id)
    self.root.after(0, setattr, self, "user_permissions", perms)
    self.root.after(0, self._log, "Permissions utilisateur chargées.", "info")

# ── Actions ───────────────────────────────────────────────────────────────

def _get_selected_streams(self) -> List[Tuple[int, str, str]]:
    """Retourne [(listbox_idx, stream_id, stream_title), …]."""
    return [
        (idx, self.stream_id_map[idx], self.streams_listbox.get(idx))
        for idx in self.streams_listbox.curselection()
    ]

def _guard_selection(self) -> bool:
    if not self.selected_user_id:
        messagebox.showwarning("Attention", "Veuillez sélectionner un utilisateur.")
        return False
    if not self.streams_listbox.curselection():
        messagebox.showwarning("Attention", "Veuillez sélectionner au moins un stream.")
        return False
    return True

def _show_current_permissions(self) -> None:
    if not self._guard_selection():
        return
    self._log("\n── Permissions actuelles ──", tag="info")
    for _, stream_id, title in self._get_selected_streams():
        perm = self.client.user_permission_on_stream(self.user_permissions, stream_id)
        if perm:
            self._log(f"  • {title}: {perm}", tag="ok")
        else:
            self._log(f"  • {title}: aucune permission", tag="skip")

def _apply_permissions(self) -> None:
    if not self._guard_selection():
        return
    capability = self.perm_var.get()
    self._log(f"\n── Application de la permission « {capability} » ──", tag="info")
    threading.Thread(
        target=self._run_apply, args=(capability,), daemon=True
    ).start()

def _run_apply(self, capability: str) -> None:
    ok = skip = err = 0
    for _, stream_id, title in self._get_selected_streams():
        existing = self.client.user_permission_on_stream(self.user_permissions, stream_id)
        if existing == capability:
            self.root.after(0, self._log, f"  ⊘ {title}: déjà « {capability} »", "skip")
            skip += 1
            continue
        success, msg = self.client.set_stream_permission(stream_id, self.selected_user_id, capability)
        if success:
            self.root.after(0, self._log, f"  ✓ {title}: {capability} appliqué", "ok")
            ok += 1
        else:
            self.root.after(0, self._log, f"  ✗ {title}: {msg}", "err")
            err += 1

    # Rafraîchir les permissions en cache
    if ok:
        self.user_permissions = self.client.get_user_permissions(self.selected_user_id)

    summary = f"\nRésumé : {ok} appliquées, {skip} ignorées, {err} erreurs"
    self.root.after(0, self._log, summary, "info")
    tag = "ok" if not err else "err"
    self.root.after(
        0,
        messagebox.showinfo if not err else messagebox.showwarning,
        "Résultat",
        summary.strip(),
    )

def _remove_permissions(self) -> None:
    if not self._guard_selection():
        return
    if not messagebox.askyesno(
        "Confirmation", "Supprimer la permission sur les streams sélectionnés ?"
    ):
        return
    self._log("\n── Suppression des permissions ──", tag="info")
    threading.Thread(target=self._run_remove, daemon=True).start()

def _run_remove(self) -> None:
    ok = err = 0
    for _, stream_id, title in self._get_selected_streams():
        success, msg = self.client.remove_stream_permission(stream_id, self.selected_user_id)
        if success:
            self.root.after(0, self._log, f"  ✓ {title}: permission supprimée", "ok")
            ok += 1
        else:
            self.root.after(0, self._log, f"  ✗ {title}: {msg}", "err")
            err += 1
    if ok:
        self.user_permissions = self.client.get_user_permissions(self.selected_user_id)
    self.root.after(0, self._log, f"\nRésumé : {ok} supprimées, {err} erreurs", "info")

# ── Sélection rapide ──────────────────────────────────────────────────────

def _select_all_streams(self) -> None:
    self.streams_listbox.select_set(0, tk.END)

def _deselect_all_streams(self) -> None:
    self.streams_listbox.selection_clear(0, tk.END)

# ── Logs ──────────────────────────────────────────────────────────────────

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
```

# ─── Point d’entrée ───────────────────────────────────────────────────────────

def main() -> None:
root = tk.Tk()
GraylogPermissionManagerGUI(root)
root.mainloop()

if **name** == “**main**”:
main()
