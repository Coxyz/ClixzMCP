"""Lecteur autonome de l'infrastructure clixz (lecture seule).

Ne dépend pas du paquet ``clixz`` : il relit directement
``/etc/clixz/config.yaml`` puis parcourt ``root_dir`` pour découvrir les
catégories, les services et leur configuration NON sensible
(``service.yaml`` + ``compose.yaml``).

Garde-fous « secrets » :
- les ``.env`` ne sont jamais lus (et, en conteneur, le FS l'interdit déjà) ;
- pour ``compose.yaml``, seuls les NOMS des variables d'environnement sont
  exposés — jamais leurs valeurs, qui pourraient contenir des secrets.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATHS = ("/etc/clixz/config.yaml",)
SERVICE_FILENAME = "service.yaml"
COMPOSE_FILENAME = "compose.yaml"

# Détails reconnus dans service.yaml (alignés sur clixz/meta.py).
_KNOWN_DETAIL_KEYS = {"summary", "features", "ports", "depends_on", "tech", "notes", "links"}


class ClixzReader:
    """Vue lecture seule de l'arborescence des services clixz."""

    def __init__(self, config_path: str | None = None, root_override: str | None = None):
        self.config_path = Path(config_path) if config_path else self._find_config()
        self.raw = self._load_yaml(self.config_path) if self.config_path else {}
        self.root = Path(root_override or self.raw.get("root_dir", "/srv/docker"))
        self.categories_cfg = self.raw.get("categories") or {}
        self.exclude = [str(p) for p in (self.raw.get("exclude") or [])]
        api = self.raw.get("api") or {}
        if isinstance(api, dict) and api.get("manifest"):
            self.manifest_path = Path(str(api["manifest"]))
        else:
            # Depuis clixz 2.2 le manifeste est généré à côté de la config.
            base = self.config_path.parent if self.config_path else Path("/etc/clixz")
            self.manifest_path = base / "manifest.json"

    # ─── config ──────────────────────────────────────────────────────────
    @staticmethod
    def _find_config() -> Path | None:
        for p in DEFAULT_CONFIG_PATHS:
            if Path(p).is_file():
                return Path(p)
        return None

    @staticmethod
    def _load_yaml(path: Path) -> dict:
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            return {}
        return data if isinstance(data, dict) else {}

    # ─── exclusions ──────────────────────────────────────────────────────
    def _rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    def _excluded(self, path: Path) -> bool:
        rel, ab = self._rel(path), path.as_posix()
        for pattern in self.exclude:
            pat = pattern.strip()
            if not pat:
                continue
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(ab, pat):
                return True
            if pat.endswith("/"):
                dir_pat = pat.rstrip("/")
                for cand in [path, *path.parents]:
                    if fnmatch.fnmatch(self._rel(cand), dir_pat) or fnmatch.fnmatch(cand.as_posix(), dir_pat):
                        return True
        return False

    # ─── découverte ──────────────────────────────────────────────────────
    def _service_dirs(self, category: str) -> list[Path]:
        cat_dir = self.root / category
        if not cat_dir.is_dir():
            return []
        try:
            entries = sorted(cat_dir.iterdir())
        except OSError:
            # Catégorie illisible (GID manquant côté conteneur) : on la traite
            # comme vide plutôt que de faire échouer tout l'inventaire à cause
            # d'une seule catégorie inaccessible.
            return []
        return [e for e in entries if e.is_dir() and not self._excluded(e)]

    def categories(self) -> list[dict]:
        """Catégories présentes sur disque ∩ config, avec leurs services."""
        out: list[dict] = []
        if not self.root.is_dir():
            return out
        for entry in sorted(self.root.iterdir()):
            if not (entry.is_dir() and entry.name in self.categories_cfg and not self._excluded(entry)):
                continue
            svcs = self._service_dirs(entry.name)
            cfg = self.categories_cfg.get(entry.name) or {}
            out.append({
                "name": entry.name,
                "owner": cfg.get("user"),
                "group": cfg.get("group"),
                "service_count": len(svcs),
                "services": [s.name for s in svcs],
            })
        return out

    def list_service_paths(self, category: str | None = None) -> list[tuple[str, str, Path]]:
        cats = [category] if category else [c["name"] for c in self.categories()]
        out: list[tuple[str, str, Path]] = []
        for c in cats:
            for p in self._service_dirs(c):
                out.append((c, p.name, p))
        return out

    def resolve(self, name: str) -> tuple[str, str, Path]:
        """Résout ``categorie/service`` ou un nom simple (doit être unique)."""
        if "/" in name:
            c, s = name.split("/", 1)
            p = self.root / c / s
            if p.is_dir() and not self._excluded(p):
                return c, s, p
            raise ValueError(f"Service introuvable : {name}")
        matches = [t for t in self.list_service_paths() if t[1] == name]
        if not matches:
            raise ValueError(f"Service introuvable : {name}")
        if len(matches) > 1:
            locs = ", ".join(f"{c}/{s}" for c, s, _ in matches)
            raise ValueError(f"Nom ambigu '{name}' (présent dans : {locs}). Utilise 'categorie/service'.")
        return matches[0]

    # ─── service.yaml ────────────────────────────────────────────────────
    def descriptor(self, category: str, service: str, path: Path) -> dict:
        f = path / SERVICE_FILENAME
        if not f.is_file():
            return {
                "key": service, "category": category, "name": service,
                "has_descriptor": False, "public": False, "kind": "infra",
                "container": service, "details": {},
            }
        try:
            raw = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            return {"key": service, "category": category, "name": service,
                    "has_descriptor": True, "_descriptor_error": str(exc), "details": {}}
        if not isinstance(raw, dict):
            raw = {}
        url = raw.get("url")
        kind = raw.get("kind") or ("app" if url else "infra")
        details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
        details = {k: v for k, v in (details or {}).items() if k in _KNOWN_DETAIL_KEYS}
        return {
            "key": service,
            "category": category,
            "name": raw.get("name") or service,
            "icon": raw.get("icon"),
            "description": raw.get("description"),
            "public": bool(raw.get("public", False)),
            "kind": kind,
            "container": raw.get("container") or service,
            "url": url,
            "tags": raw.get("tags") or [],
            "details": details,
            "has_descriptor": True,
        }

    # ─── compose.yaml (non sensible) ─────────────────────────────────────
    def compose(self, path: Path) -> dict:
        f = path / COMPOSE_FILENAME
        info: dict[str, Any] = {"present": f.is_file()}
        if not f.is_file():
            return info
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            info["_error"] = str(exc)
            return info
        if not isinstance(data, dict):
            return info
        services = data.get("services") or {}
        info["services"] = {
            name: self._compose_service(sdef)
            for name, sdef in services.items()
            if isinstance(sdef, dict)
        }
        info["networks"] = list((data.get("networks") or {}).keys())
        info["named_volumes"] = list((data.get("volumes") or {}).keys())
        return info

    @staticmethod
    def _env_keys(env: Any) -> list[str]:
        """NOMS des variables d'env uniquement — valeurs masquées (secrets possibles)."""
        if isinstance(env, dict):
            return list(env.keys())
        if isinstance(env, list):
            keys = []
            for item in env:
                if isinstance(item, str):
                    keys.append(item.split("=", 1)[0])
            return keys
        return []

    @staticmethod
    def _as_list(val: Any) -> list[str]:
        if val is None:
            return []
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)]

    @staticmethod
    def _depends_on(val: Any) -> list[str]:
        if isinstance(val, dict):
            return list(val.keys())
        if isinstance(val, list):
            return [str(v) for v in val]
        return []

    @staticmethod
    def _build_info(val: Any) -> Any:
        if val is None:
            return None
        if isinstance(val, str):
            return {"context": val}
        if isinstance(val, dict):
            return {k: val.get(k) for k in ("context", "dockerfile", "target") if val.get(k)}
        return None

    def _compose_service(self, sdef: dict) -> dict:
        ef = sdef.get("env_file")
        hc = sdef.get("healthcheck") if isinstance(sdef.get("healthcheck"), dict) else None
        out = {
            "image": sdef.get("image"),
            "build": self._build_info(sdef.get("build")),
            "container_name": sdef.get("container_name"),
            "restart": sdef.get("restart"),
            "expose": self._as_list(sdef.get("expose")),
            "ports": self._as_list(sdef.get("ports")),
            "volumes": self._as_list(sdef.get("volumes")),
            "networks": self._depends_on(sdef.get("networks")),
            "depends_on": self._depends_on(sdef.get("depends_on")),
            "env_file": self._as_list(ef),
            # NOMS uniquement — valeurs jamais exposées.
            "environment_keys": self._env_keys(sdef.get("environment")),
            "user": sdef.get("user"),
            "read_only": sdef.get("read_only"),
            "cap_drop": self._as_list(sdef.get("cap_drop")),
            "security_opt": self._as_list(sdef.get("security_opt")),
            "mem_limit": sdef.get("mem_limit"),
            "cpus": sdef.get("cpus"),
            "healthcheck_test": hc.get("test") if hc else None,
        }
        return {k: v for k, v in out.items() if v not in (None, [], {})}

    # ─── manifest agrégé ─────────────────────────────────────────────────
    def manifest(self) -> dict | None:
        f = self.manifest_path
        if not f.is_file():
            return None
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
