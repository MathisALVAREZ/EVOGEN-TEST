# -*- coding: utf-8 -*-
"""Outil de gestion des permissions utilisateurs Graylog avec interface graphique."""

import base64
import logging
from typing import Any, Dict, Optional, List
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import urllib3
import json

from secret import GRAYLOG_URL, GRAYLOG_USERNAME, GRAYLOG_PASSWORD

# Désactiver les avertissements SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class GraylogClient:
    """Client pour l'API Graylog."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(self._default_headers())

    def _default_headers(self) -> Dict[str, str]:
        return {
            "Authorization": self._auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-By": "python-script",
        }

    def _auth_header(self) -> str:
        creds = f"{GRAYLOG_USERNAME}:{GRAYLOG_PASSWORD}"
        b64 = base64.b64encode(creds.encode("utf-8")).decode("utf-8")
        return f"Basic {b64}"

    def _request(self, method: str, path: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        url = f"{GRAYLOG_URL}{path}"
        try:
            resp = self.session.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as err:
            logger.error("%s %s -> %s", method.upper(), url, err)
            if hasattr(err, 'response') and err.response is not None:
                logger.error("Response body: %s", err.response.text[:500])
            return None

    def get_streams(self) -> Dict[str, str]:
        """Retourne {stream_id: titre}."""
        data = self._request("get", "/api/streams")
        if not data:
            return {}
        streams = {}
        for s in data.get("streams", []):
            streams[s["id"]] = s.get("title", "Unknown")
        logger.info("%d streams récupérés", len(streams))
        return streams

    def get_users(self) -> Dict[str, str]:
        """Retourne {user_id: username}."""
        data = self._request("get", "/api/users")
        if not data:
            return {}
        users = {}
        for u in data.get("users", []):
            users[u["id"]] = u.get("username", "Unknown")
        logger.info("%d utilisateurs récupérés", len(users))
        return users

    def get_user_permissions(self, user_id: str) -> Dict[str, Any]:
        """Récupère toutes les permissions d'un utilisateur via /api/authz/shares/user/{userId}."""
        data = self._request("get", f"/api/authz/shares/user/{user_id}")
        if data is not None:
            logger.info("Permissions récupérées pour l'utilisateur %s", user_id)
            return data
        logger.error("Impossible de récupérer les permissions pour l'utilisateur %s", user_id)
        return {}

    def set_stream_permissions(
        self, stream_id: str, user_id: str, permission: str = "view"
    ) -> bool:
        """Définit les permissions pour un utilisateur sur un stream."""
        
        # Construire le GRN (Graylog Resource Name) pour le stream
        stream_grn = f"grn::::stream:{stream_id}"
        user_grn = f"grn::::user:{user_id}"
        
        # Endpoint pour modifier les permissions d'une entité
        #endpoint = f"/api/authz/shares/entities/{stream_grn}/grantees/{user_grn}"
        
        endpoint = f"/api/authz/shares/entities/{stream_id}/grantees/{user_grn}"

        payload = {
            "capability": permission
        }
        
        logger.info(f"Tentative PUT {endpoint} avec payload: {json.dumps(payload)}")
        
        try:
            url = f"{GRAYLOG_URL}{endpoint}"
            resp = self.session.request("put", url, json=payload)
            
            if resp.status_code in [200, 201, 204]:
                logger.info("Permission %s appliquée sur %s pour %s", 
                           permission, stream_id, user_id)
                return True
            else:
                logger.error(f"Status {resp.status_code}: {resp.text[:200]}")
                return False
        except Exception as e:
            logger.error(f"Erreur: {e}")
            return False

    def user_has_permission_on_stream(self, user_permissions: Dict[str, Any], stream_id: str) -> Optional[str]:
        """Vérifie si un utilisateur a des permissions sur un stream spécifique."""
        
        if not user_permissions:
            return None
        
        # Accéder au contexte et aux grantee_capabilities
        context = user_permissions.get("context", {})
        grantee_capabilities = context.get("grantee_capabilities", {})
        
        stream_grn = f"grn::::stream:{stream_id}"
        
        if stream_grn in grantee_capabilities:
            return grantee_capabilities[stream_grn]
        
        return None


class GraylogPermissionManagerGUI:
    """Interface graphique pour gérer les permissions Graylog."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Graylog Permission Manager")
        self.root.geometry("1000x700")
        
        self.client = GraylogClient()
        self.streams: Dict[str, str] = {}
        self.users: Dict[str, str] = {}
        self.stream_id_map: Dict[int, str] = {}
        self.selected_user: Optional[str] = None
        self.user_permissions: Dict[str, Any] = {}
        
        self._build_ui()
        self._load_data()

    def _build_ui(self) -> None:
        """Construit l'interface utilisateur."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # === SECTION UTILISATEURS ===
        user_frame = ttk.LabelFrame(main_frame, text="Sélectionner un utilisateur", padding="10")
        user_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(user_frame, text="Utilisateur:").pack(side=tk.LEFT, padx=5)
        self.user_var = tk.StringVar()
        self.user_combo = ttk.Combobox(user_frame, textvariable=self.user_var, state="viewonly", width=40)
        self.user_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.user_combo.bind("<<ComboboxSelected>>", self._on_user_selected)
        
        # === SECTION STREAMS ===
        streams_frame = ttk.LabelFrame(main_frame, text="Sélectionner les streams", padding="10")
        streams_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        scrollbar = ttk.Scrollbar(streams_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.streams_listbox = tk.Listbox(
            streams_frame,
            yscrollcommand=scrollbar.set,
            selectmode=tk.MULTIPLE,
            height=15
        )
        self.streams_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.streams_listbox.yview)
        
        # === SECTION PERMISSIONS ===
        perm_frame = ttk.LabelFrame(main_frame, text="Permissions à appliquer", padding="10")
        perm_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.perm_var = tk.StringVar(value="view")
        ttk.Label(perm_frame, text="Type de permission:").pack(side=tk.LEFT, padx=5)
        
        for perm in ["view", "manage", "own"]:
            ttk.Radiobutton(
                perm_frame,
                text=perm.capitalize(),
                variable=self.perm_var,
                value=perm
            ).pack(side=tk.LEFT, padx=10)
        
        # === SECTION ACTIONS ===
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(
            action_frame,
            text="Afficher les permissions actuelles",
            command=self._show_current_permissions
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            action_frame,
            text="Appliquer les permissions",
            command=self._apply_permissions
        ).pack(side=tk.LEFT, padx=5)
        
        # === SECTION LOGS ===
        log_frame = ttk.LabelFrame(main_frame, text="Logs", padding="10")
        log_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        scrollbar_log = ttk.Scrollbar(log_frame)
        scrollbar_log.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(log_frame, height=8, yscrollcommand=scrollbar_log.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_log.config(command=self.log_text.yview)
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

    def _load_data(self) -> None:
        """Charge les streams et utilisateurs depuis Graylog."""
        self._log("Chargement des données...")
        
        try:
            self.streams = self.client.get_streams()
            self.users = self.client.get_users()
            
            user_list = [f"{username} ({uid})" for uid, username in self.users.items()]
            self.user_combo["values"] = user_list
            
            self.stream_id_map.clear()
            idx = 0
            for stream_id, title in sorted(self.streams.items(), key=lambda x: x[1]):
                self.streams_listbox.insert(tk.END, title)
                self.stream_id_map[idx] = stream_id
                idx += 1
            
            self._log(f"✓ {len(self.streams)} streams chargés")
            self._log(f"✓ {len(self.users)} utilisateurs chargés")
        except Exception as e:
            self._log(f"✗ Erreur lors du chargement: {e}")
            messagebox.showerror("Erreur", f"Impossible de charger les données: {e}")

    def _on_user_selected(self, event=None) -> None:
        """Appelé quand un utilisateur est sélectionné."""
        selection = self.user_var.get()
        if selection:
            self.selected_user = selection.split("(")[-1].rstrip(")")
            self._log(f"Utilisateur sélectionné: {selection}")
            
            self.user_permissions = self.client.get_user_permissions(self.selected_user)
            self._log(f"Permissions de l'utilisateur chargées")

    def _show_current_permissions(self) -> None:
        """Affiche les permissions actuelles pour les streams sélectionnés."""
        if not self.selected_user:
            messagebox.showwarning("Attention", "Veuillez sélectionner un utilisateur")
            return
        
        if not self.streams_listbox.curselection():
            messagebox.showwarning("Attention", "Veuillez sélectionner au moins un stream")
            return
        
        self._log("\n--- Permissions actuelles ---")
        
        for idx in self.streams_listbox.curselection():
            stream_id = self.stream_id_map[idx]
            stream_title = self.streams_listbox.get(idx)
            
            existing_perm = self.client.user_has_permission_on_stream(self.user_permissions, stream_id)
            
            if existing_perm:
                self._log(f"  • {stream_title}: {existing_perm}")
            else:
                self._log(f"  • {stream_title}: Aucune permission")

    def _apply_permissions(self) -> None:
        """Applique les permissions sélectionnées."""
        if not self.selected_user:
            messagebox.showwarning("Attention", "Veuillez sélectionner un utilisateur")
            return
        
        if not self.streams_listbox.curselection():
            messagebox.showwarning("Attention", "Veuillez sélectionner au moins un stream")
            return
        
        permission = self.perm_var.get()
        user_id = self.selected_user
        
        self._log(f"\n--- Application des permissions ({permission}) ---")
        
        success_count = 0
        skip_count = 0
        error_count = 0
        
        for idx in self.streams_listbox.curselection():
            stream_id = self.stream_id_map[idx]
            stream_title = self.streams_listbox.get(idx)
            
            existing_perm = self.client.user_has_permission_on_stream(self.user_permissions, stream_id)
            
            if existing_perm == permission:
                self._log(f"  ⊘ {stream_title}: Permission {permission} déjà appliquée")
                skip_count += 1
                continue
            
            if self.client.set_stream_permissions(stream_id, user_id, permission):
                self._log(f"  ✓ {stream_title}: Permission {permission} appliquée")
                success_count += 1
                self.user_permissions = self.client.get_user_permissions(user_id)
            else:
                self._log(f"  ✗ {stream_title}: Erreur lors de l'application")
                error_count += 1
        
        self._log(f"\nRésumé: {success_count} appliquées, {skip_count} ignorées, {error_count} erreurs")
        
        if error_count == 0:
            messagebox.showinfo("Succès", f"{success_count} permissions appliquées, {skip_count} ignorées")
        else:
            messagebox.showwarning("Attention", f"{success_count} appliquées, {skip_count} ignorées, {error_count} erreurs")

    def _log(self, message: str) -> None:
        """Ajoute un message au widget de log."""
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update()


def main() -> None:
    root = tk.Tk()
    app = GraylogPermissionManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
