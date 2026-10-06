"""Client de la passerelle `clixz` (``clixz-mcpd``).

Le serveur MCP ne peut pas exécuter `clixz` lui-même : le conteneur n'a ni le
binaire, ni les capacités, ni un montage inscriptible de ``/srv/docker``. Il
délègue à un démon **non privilégié** de l'hôte, joint par socket Unix.

Depuis clixz 2.0 il n'existe plus de démon privilégié en aval. Les verbes
mutants ne sont pas exécutés : ils sont transmis à la CLI avec ``--plan``, qui
imprime ce qu'elle ferait et n'écrit rien. L'unité systemd porte
``ReadOnlyPaths=/srv/docker`` — ce n'est pas une règle que le démon s'applique,
c'est une chose qu'il ne peut pas faire.

La liste blanche est réappliquée ici, côté client : commodité (erreur immédiate
et lisible), pas barrière de sécurité — celle-ci est côté démon, seul endroit
qui compte puisqu'il est le seul à exécuter quoi que ce soit.

Configuration :
  CLIXZ_MCPD_SOCKET   chemin de la socket (def. /run/clixz-mcpd/clixz-mcpd.sock,
                      repli sur l'ancienne /run/clixz-runner/ tant qu'elle existe)
  CLIXZ_MCPD_TIMEOUT  délai d'attente côté client, en secondes (def. 70)
"""

from __future__ import annotations

import json
import os
import socket

import compat

SOCKET_PATH = compat.env("MCPD_SOCKET") or compat.first_existing(
    "/run/clixz-mcpd/clixz-mcpd.sock",
    "/run/clixz-runner/clixz-runner.sock",
)
TIMEOUT = float(compat.env("MCPD_TIMEOUT", "70"))
# `plan` couvre tous les verbes mutants (new, fix, rm, category-add, repo-add,
# repo-rm). Il n'y a plus d'`apply` : l'exécution appartient à l'humain, au clavier.
ALLOWED = ("ls", "show", "check", "manifest", "exposed", "config", "rules",
           "repos", "categories", "plan")


class RunnerUnavailable(RuntimeError):
    """La passerelle n'est pas joignable (non installée, arrêtée, non montée)."""


def available() -> bool:
    return os.path.exists(SOCKET_PATH)


def run(cmd: str, **params) -> dict:
    """Exécute une commande clixz via la passerelle et renvoie sa réponse.

    Renvoie un dict : ``exit_code``, ``stdout``, ``stderr`` — ou ``error``.
    ``exit_code`` non nul n'est pas forcément un échec : ``clixz check`` sort
    en non-zéro dès qu'il constate une dérive.
    """
    if cmd not in ALLOWED:
        raise ValueError(
            f"commande non autorisée : {cmd!r} (autorisées : {', '.join(ALLOWED)})"
        )
    if not available():
        raise RunnerUnavailable(
            f"passerelle clixz indisponible ({SOCKET_PATH}). Le service "
            "clixz-mcpd est-il démarré sur l'hôte, et la socket montée "
            "dans le conteneur ?"
        )

    payload = json.dumps({"cmd": cmd, **params}, ensure_ascii=False).encode("utf-8") + b"\n"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(SOCKET_PATH)
            sock.sendall(payload)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if chunks[-1].endswith(b"\n"):
                    break
    except (OSError, socket.timeout) as exc:
        raise RunnerUnavailable(f"passerelle clixz injoignable : {exc}") from exc

    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not raw:
        raise RunnerUnavailable("réponse vide de la passerelle clixz.")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise RunnerUnavailable(f"réponse illisible de la passerelle : {exc}") from exc
