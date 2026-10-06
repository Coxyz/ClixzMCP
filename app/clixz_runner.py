"""Client de la passerelle `clixz` (``clixz-mcpd``).

Le serveur MCP n'exécute pas `clixz` lui-même : le conteneur n'a ni le binaire,
ni les capacités, ni un montage inscriptible de ``/srv/docker``. Il s'adresse à
un démon **non privilégié** de l'hôte, par socket Unix.

Depuis clixz 2.3, ce démon a deux façons de répondre :

- les **lectures** (``ls``, ``check``, ``rules``, ``todo``…) passent par la CLI,
  sur l'hôte, sans privilège. Réponse : ``exit_code``, ``stdout`` (du JSON),
  ``stderr`` ;
- les **plans de service**, leur **application**, la liste des plans,
  ``exposed`` et les **écritures de la todo** sont relayés à ``clixz-apply``,
  un processus root démarré pour cette seule requête. Réponse : un objet JSON
  direct, avec ``ok``.

La liste blanche est réappliquée ici, côté client : commodité (erreur immédiate
et lisible), pas barrière de sécurité. Les barrières sont le démon, puis
``clixz-apply``, qui revalident tout.

Configuration :
  CLIXZ_MCPD_SOCKET   chemin de la socket (def. /run/clixz-mcpd/clixz-mcpd.sock)
  CLIXZ_MCPD_TIMEOUT  délai d'attente côté client, en secondes (def. 130 : un apply
                      peut prendre le temps de créer une stack Komodo)
"""

from __future__ import annotations

import json
import os
import socket

SOCKET_PATH = os.environ.get("CLIXZ_MCPD_SOCKET", "").strip() or "/run/clixz-mcpd/clixz-mcpd.sock"
TIMEOUT = float(os.environ.get("CLIXZ_MCPD_TIMEOUT", "").strip() or "130")
MAX_RESPONSE = 8 * 1024 * 1024

ALLOWED = (
    # lectures, par la CLI
    "ls", "show", "check", "manifest", "config", "rules", "repos", "categories",
    "todo", "todo-show", "version",
    # plans (service : relayés à clixz-apply ; catégorie et dépôt : CLI --plan)
    "plan",
    # relayés à clixz-apply
    "plans", "plan-show", "plan-drop", "apply", "exposed",
    "todo-add", "todo-edit", "todo-rm",
)


class RunnerUnavailable(RuntimeError):
    """La passerelle n'est pas joignable (non installée, arrêtée, non montée)."""


def available() -> bool:
    return os.path.exists(SOCKET_PATH)


def run(cmd: str, **params) -> dict:
    """Envoie une requête à la passerelle et renvoie sa réponse (un dict)."""
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
    chunks: list[bytes] = []
    size = 0
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(SOCKET_PATH)
            sock.sendall(payload)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_RESPONSE:
                    raise RunnerUnavailable("réponse de la passerelle trop volumineuse")
                if chunk.endswith(b"\n"):
                    break
    except (OSError, socket.timeout) as exc:
        raise RunnerUnavailable(f"passerelle clixz injoignable : {exc}") from exc

    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not raw:
        raise RunnerUnavailable("réponse vide de la passerelle clixz.")
    try:
        answer = json.loads(raw)
    except ValueError as exc:
        raise RunnerUnavailable(f"réponse illisible de la passerelle : {exc}") from exc
    if not isinstance(answer, dict):
        raise RunnerUnavailable("réponse inattendue de la passerelle.")
    return answer


def cli_json(cmd: str, **params) -> dict:
    """Une lecture par la CLI, dont le ``stdout`` JSON est décodé.

    Renvoie le JSON de la commande, ou ``{"error": …}``. ``exit_code`` est
    ajouté quand il n'est pas nul (``check`` sort en 1 sur une dérive : c'est
    un résultat, pas un échec).
    """
    answer = run(cmd, **params)
    if not answer.get("ok"):
        return {"error": answer.get("error") or "échec de la passerelle"}
    try:
        data = json.loads(answer.get("stdout") or "")
    except ValueError:
        detail = (answer.get("stderr") or answer.get("stdout") or "").strip()
        return {"error": detail or "sortie illisible", "exit_code": answer.get("exit_code")}
    if not isinstance(data, dict):
        return {"result": data}
    if answer.get("exit_code"):
        data.setdefault("exit_code", answer["exit_code"])
    return data
