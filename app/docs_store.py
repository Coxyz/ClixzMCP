"""Accès aux documents de référence Coxyz (``/srv/docs``).

Ces documents Markdown décrivent les **règles et conventions** de
l'infrastructure (compose, réseau, permissions, durcissement…). Contrairement à
``clixz_reader``, ce module peut **écrire** : il sert à créer et mettre à jour
ces docs pour que le contexte reste à jour.

Arborescence attendue : ``<root>/<catégorie>/<nom>.md`` (une catégorie = un
sous-dossier ; ex. ``conventions/network-ports.md``).

Garde-fous d'écriture — la lecture seule n'étant plus garantie par le système de
fichiers pour ce dossier, tout repose ici :
- écritures confinées à ``root`` : chaque segment de chemin est validé, et le
  chemin final est vérifié **après** résolution des liens symboliques ;
- extension ``.md`` imposée, aucun autre type de fichier n'est écrit ;
- ``create`` refuse d'écraser un fichier existant, ``update`` refuse d'en créer
  un ;
- écriture **atomique** (fichier temporaire + ``os.replace``) et conservation de
  la version précédente en ``.bak`` ;
- taille de contenu plafonnée.
"""

from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

DOC_SUFFIX = ".md"
BACKUP_SUFFIX = ".bak"
ARCHIVE_DIRNAME = ".archived"
MAX_BYTES = 1_048_576  # 1 MiB — un document de référence, pas un dépôt de données.

# Catégories que le serveur peut lire mais jamais écrire.
#
# Ces dossiers contiennent les RÈGLES que l'assistant doit suivre. S'il pouvait
# les réécrire, il lui suffirait de modifier une convention puis de se citer
# lui-même comme autorité à la session suivante : la contrainte deviendrait
# circulaire. La barrière réelle est posée sur le système de fichiers (dossiers
# en 2755, fichiers en 644, propriétaire humain) ; la liste ci-dessous ne sert
# qu'à renvoyer une erreur explicite au lieu d'un EACCES opaque.
READONLY_CATEGORIES = ("conventions", "hardening")

# Un segment (catégorie ou nom de fichier) : pas de séparateur, pas de "..",
# pas de nom caché. Volontairement restrictif.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class DocsError(ValueError):
    """Erreur d'usage (chemin invalide, doc absent, écriture désactivée…)."""


class DocsStore:
    """Vue sur ``/srv/docs``. L'écriture n'est permise que si ``writable``."""

    def __init__(self, root: str | Path = "/srv/docs", writable: bool = False):
        self.root = Path(root)
        self.writable = writable

    # ─── validation des chemins ──────────────────────────────────────────
    @staticmethod
    def _check_segment(seg: str, kind: str) -> str:
        # Pas de strip("/") : un segment contenant un séparateur doit être
        # REFUSÉ, non réécrit silencieusement en quelque chose de valide.
        seg = (seg or "").strip()
        if not seg or not _SEGMENT_RE.match(seg):
            raise DocsError(
                f"{kind} invalide : '{seg}'. Autorisé : lettres, chiffres, "
                "'.', '-', '_' ; pas de '/' ni de '..'."
            )
        return seg

    def _confine(self, path: Path) -> Path:
        """Vérifie que ``path`` reste sous ``root``, liens symboliques résolus."""
        root = self.root.resolve()
        # strict=False : la cible peut ne pas exister encore (création).
        resolved = path.resolve()
        if resolved != root and root not in resolved.parents:
            raise DocsError("Chemin hors du dossier de documentation.")
        return resolved

    def _path(self, category: str, name: str) -> Path:
        category = self._check_segment(category, "Catégorie")
        name = self._check_segment(name, "Nom de document")
        if not name.endswith(DOC_SUFFIX):
            name += DOC_SUFFIX
        return self._confine(self.root / category / name)

    # ─── découverte ──────────────────────────────────────────────────────
    def categories(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(
            e.name for e in self.root.iterdir()
            if e.is_dir() and not e.name.startswith(".")
        )

    def _doc_files(self, category: str | None = None) -> list[tuple[str, Path]]:
        cats = [self._check_segment(category, "Catégorie")] if category else self.categories()
        out: list[tuple[str, Path]] = []
        for c in cats:
            d = self.root / c
            if not d.is_dir():
                continue
            for f in sorted(d.iterdir()):
                if f.is_file() and f.suffix == DOC_SUFFIX and not f.name.startswith("."):
                    out.append((c, f))
        return out

    def resolve(self, doc: str) -> tuple[str, Path]:
        """Résout ``catégorie/nom`` ou un nom simple (qui doit être unique)."""
        ref = (doc or "").strip().strip("/")
        if not ref:
            raise DocsError("Référence de document vide.")
        if "/" in ref:
            category, name = ref.split("/", 1)
            p = self._path(category, name)
            if not p.is_file():
                raise DocsError(f"Document introuvable : {ref}")
            return category, p
        stem = ref[: -len(DOC_SUFFIX)] if ref.endswith(DOC_SUFFIX) else ref
        matches = [(c, f) for c, f in self._doc_files() if f.stem == stem]
        if not matches:
            raise DocsError(f"Document introuvable : {ref}")
        if len(matches) > 1:
            locs = ", ".join(f"{c}/{f.name}" for c, f in matches)
            raise DocsError(
                f"Nom ambigu '{ref}' (présent dans : {locs}). Utilise 'catégorie/nom'."
            )
        return matches[0]

    # ─── métadonnées ─────────────────────────────────────────────────────
    @staticmethod
    def _title(text: str) -> str | None:
        for line in text.splitlines():
            if line.startswith("# "):
                return line[2:].strip()
        return None

    @staticmethod
    def _headings(text: str) -> list[str]:
        """Plan du document (titres de niveau 2), pour se repérer sans tout lire."""
        return [
            line[3:].strip()
            for line in text.splitlines()
            if line.startswith("## ")
        ]

    def _meta(self, category: str, path: Path, text: str | None = None) -> dict:
        st = path.stat()
        meta = {
            "doc": f"{category}/{path.name}",
            "category": category,
            "name": path.name,
            "bytes": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            .isoformat(timespec="seconds"),
        }
        if text is not None:
            meta["title"] = self._title(text)
            meta["headings"] = self._headings(text)
        return meta

    # ─── lecture ─────────────────────────────────────────────────────────
    def list(self, category: str | None = None) -> list[dict]:
        out: list[dict] = []
        for c, f in self._doc_files(category):
            try:
                text = f.read_text(encoding="utf-8")
            except OSError as exc:
                out.append({"doc": f"{c}/{f.name}", "category": c,
                            "name": f.name, "_error": str(exc)})
                continue
            out.append(self._meta(c, f, text))
        return out

    def get(self, doc: str) -> dict:
        category, path = self.resolve(doc)
        text = path.read_text(encoding="utf-8")
        return {**self._meta(category, path, text), "content": text}

    # ─── écriture ────────────────────────────────────────────────────────
    def _require_writable(self, category: str | None = None) -> None:
        if not self.writable:
            raise DocsError(
                "Écriture désactivée sur ce serveur (COXYZ_DOCS_RW absent, ou "
                "dossier monté en lecture seule)."
            )
        if category and category in READONLY_CATEGORIES:
            raise DocsError(
                f"La catégorie '{category}' est en lecture seule : elle contient "
                "les règles que tu dois suivre, tu ne peux pas les modifier. "
                "Signale la correction souhaitée à l'utilisateur."
            )

    @staticmethod
    def _check_content(content: str) -> str:
        if not isinstance(content, str) or not content.strip():
            raise DocsError("Contenu vide.")
        if len(content.encode("utf-8")) > MAX_BYTES:
            raise DocsError(f"Contenu trop volumineux (max {MAX_BYTES} octets).")
        return content if content.endswith("\n") else content + "\n"

    def _write_atomic(self, path: Path, content: str) -> None:
        """Écrit via un temporaire dans le même dossier, puis ``os.replace``.

        Un lecteur concurrent voit soit l'ancienne version, soit la nouvelle,
        jamais un fichier tronqué.
        """
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=DOC_SUFFIX)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o664)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def create(self, category: str, name: str, content: str) -> dict:
        self._require_writable(category)
        content = self._check_content(content)
        path = self._path(category, name)
        if path.exists():
            raise DocsError(
                f"Le document {category}/{path.name} existe déjà — utilise update_doc."
            )
        if not path.parent.exists():
            path.parent.mkdir(mode=0o775, parents=False)
        self._write_atomic(path, content)
        return {**self._meta(category, path, content), "created": True}

    def update(self, doc: str, content: str, mode: str = "replace") -> dict:
        self._require_writable()
        if mode not in ("replace", "append"):
            raise DocsError("mode invalide : attendu 'replace' ou 'append'.")
        category, path = self.resolve(doc)
        self._require_writable(category)
        previous = path.read_text(encoding="utf-8")
        if mode == "append":
            sep = "" if previous.endswith("\n") else "\n"
            content = previous + sep + content
        content = self._check_content(content)
        # Filet de sécurité : une écriture erronée reste rattrapable.
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        try:
            self._write_atomic(backup, previous)
        except OSError:
            pass  # pas de .bak possible : on n'empêche pas la mise à jour pour autant
        self._write_atomic(path, content)
        return {
            **self._meta(category, path, content),
            "updated": True,
            "mode": mode,
            "previous_bytes": len(previous.encode("utf-8")),
            "backup": backup.name,
        }

    def delete(self, doc: str) -> dict:
        """Retire un document de l'index — en l'archivant, jamais en le détruisant.

        L'appelant voit une suppression ; sur le disque le fichier est déplacé
        sous ``<root>/.archived/<catégorie>/<horodatage>-<nom>``. Le dossier
        commence par un point et n'est donc jamais listé comme une catégorie :
        le document disparaît de ``list`` et de ``get`` sans être perdu.
        """
        self._require_writable()
        category, path = self.resolve(doc)
        self._require_writable(category)

        dest_dir = self.root / ARCHIVE_DIRNAME / category
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = dest_dir / f"{stamp}-{path.name}"
        dest_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        bytes_before = path.stat().st_size
        path.replace(dest)

        # Une éventuelle sauvegarde .bak suit le document, sinon elle resterait
        # orpheline dans la catégorie.
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        if backup.is_file():
            backup.replace(dest_dir / f"{stamp}-{backup.name}")

        return {
            "doc": f"{category}/{path.name}",
            "category": category,
            "name": path.name,
            "deleted": True,
            "bytes": bytes_before,
            "archived_to": str(dest),
        }
