"""Serveur MCP pour l'infrastructure Docker Boxyz, gérée par la CLI `clixz`.

Donne aux assistants IA, via le Model Context Protocol :
- l'inventaire des services et leur configuration NON sensible ;
- l'audit des permissions et des compose, l'exposition réelle par le proxy ;
- les règles de compose en vigueur et les écarts acceptés ;
- des PLANS de création, modification, correction et archivage de service,
  que l'IA applique (`plan_apply`) après l'accord de l'utilisateur ;
- la todo de l'opérateur, en lecture et en écriture ;
- les dépôts git de /opt/repos et la documentation de /srv/docs.

Aucun secret (.env) n'est accessible, et rien n'est écrit par ce conteneur dans
/srv/docker : il le monte en lecture seule. Les écritures passent par la
passerelle de l'hôte (`clixz-mcpd`), qui les relaie à `clixz-apply`, un
processus root démarré pour une requête, qui revalide tout. Seuls les
documents de /srv/docs sont écrits d'ici, et seulement si CLIXZ_DOCS_RW est
activé. Transport HTTP « streamable-http », derrière le reverse proxy.

Authentification — deux modes :
  • OAuth (si OAUTH_ISSUER défini) : le serveur agit en Resource Server, publie
    les métadonnées OAuth pointant vers l'IdP (Auth0), et valide les JWT émis par
    lui. C'est l'IdP qui gère login/consentement. Endpoint sur /mcp.
  • Chemin secret (sinon) : endpoint servi sur /<MCP_AUTH_TOKEN>/mcp (ou /mcp si
    vide). Aucun 401 → pas de bascule OAuth. Utile pour tester en local.

Variables d'environnement :
  MCP_HOST / MCP_PORT      (def. 0.0.0.0 / 8000)
  CLIXZ_CONFIG / CLIXZ_ROOT
  MCP_AUTH_TOKEN           secret de chemin (mode non-OAuth uniquement)
  OAUTH_ISSUER / OAUTH_AUDIENCE / OAUTH_RESOURCE_URL / OAUTH_REQUIRED_SCOPES
                           voir auth.py (active le mode OAuth)
  CLIXZ_DOCS               racine des documents de référence (def. /srv/docs)
  CLIXZ_DOCS_RW            "1" pour autoriser document_create/update/delete (def. non)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

import clixz_runner
from auth import JWTVerifier, oauth_config
from clixz_reader import ClixzReader
from docs_store import DocsError, DocsStore


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"CLIXZ_{name}", "").strip() or default


CONFIG_PATH = _env("CONFIG", "/etc/clixz/config.yaml")
ROOT_OVERRIDE = _env("ROOT") or None
HOST = os.environ.get("MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("MCP_PORT", "8000"))
DOCS_ROOT = _env("DOCS", "/srv/docs")
DOCS_RW = _env("DOCS_RW") not in ("", "0", "false", "False")

INSTRUCTIONS = (
    "Serveur MCP de l'infrastructure Docker Boxyz, gérée par la CLI `clixz` "
    "(root_dir /srv/docker). Les outils sont groupés par préfixe.\n"
    "\n"
    "• todo_* — CE QUI RESTE À FAIRE. Consulte todo_list au début de toute "
    "conversation sur l'infrastructure : c'est la liste de l'opérateur, et la "
    "tienne. Tu as les mêmes droits que lui : créer, modifier, changer l'état "
    "(todo, doing, done, archived), supprimer. Ajoute ce que tu découvres et "
    "qui reste à faire ; passe en done ce que tu as terminé.\n"
    "\n"
    "• service_* — INVENTAIRE et CHANGEMENTS. service_list, service_read et "
    "service_search lisent service.yaml et compose.yaml : jamais les valeurs du "
    ".env, seulement les noms des variables. service_check audite les "
    "permissions et analyse les compose. service_exposed lit, au moment de "
    "l'appel, ce que le reverse proxy publie : c'est le seul outil qui voit "
    "l'exposition Internet.\n"
    "  Un changement se fait en DEUX TEMPS.\n"
    "  1. service_create (nouveau service : son compose et son service.yaml), "
    "service_update (remplacer le compose.yaml et/ou le service.yaml d'un "
    "service existant — passe le fichier COMPLET), service_fix (permissions) et "
    "service_delete (archivage) renvoient un PLAN : commandes, diff, constats du "
    "lint. Rien n'est écrit. Un plan dont le compose porterait une erreur de "
    "lint non acceptée dans ignore.yaml est REFUSÉ (`blocked`) : corrige et "
    "redemande.\n"
    "  2. Montre le plan à l'utilisateur — le diff et les constats — et "
    "n'appelle plan_apply(plan_id) qu'après son accord EXPLICITE ; son client "
    "lui demandera aussi de valider l'appel. N'affirme jamais qu'un changement "
    "est fait sans le résultat de plan_apply.\n"
    "  Un plan vaut une heure, s'applique une seule fois, et il est refusé si le "
    "service a changé entre-temps : refais-le. plan_list montre les plans en "
    "attente, plan_read en détaille un, plan_delete en supprime un.\n"
    "  clixz n'écrit JAMAIS le .env : l'opérateur le remplit dans Komodo. Et "
    "clixz ne DÉPLOIE rien : un nouveau service a sa stack créée dans Komodo, où "
    "l'opérateur renseigne l'environnement puis déploie ; une modification prend "
    "effet quand il redéploie. Dis-le-lui après chaque plan_apply.\n"
    "  Le compose fait autorité. Le durcissement attendu : cap_drop ALL, "
    "no-new-privileges, user non root, restart, rotation des logs, image "
    "épinglée (jamais :latest), ports en 127.0.0.1: sauf besoin LAN explicite, "
    "chemins hôte absolus (/srv/docker/<catégorie>/<service>/config ou data). "
    "Ces attentes sont des RÈGLES à identifiant dont le niveau est fixé par "
    "l'opérateur : boxyz_rules donne les règles en vigueur et les écarts qu'il "
    "a acceptés, service par service, avec leur raison. Ne présente pas comme "
    "un problème un écart déjà accepté. Sans compose fourni, service_create "
    "propose le gabarit durci de la catégorie : une bonne base de départ.\n"
    "\n"
    "• categorie_* et repo_* — catégories (et leur compte système) et dépôts git "
    "de /opt/repos. categorie_create, repo_create et repo_delete renvoient un "
    "plan que l'opérateur tape lui-même : ils ne s'appliquent pas d'ici.\n"
    "\n"
    "• document_* — la documentation de /srv/docs : règles et conventions. "
    "Consulte-la avant de proposer une configuration. Les catégories "
    "'conventions' et 'hardening' sont en LECTURE SEULE : ce sont les règles "
    "qui te contraignent. Si une règle te paraît fausse, dis-le à l'utilisateur.\n"
    "\n"
    "• boxyz_* — configuration propre à cet hôte : boxyz_config "
    "(/etc/clixz/config.yaml), boxyz_rules (lint.yaml et ignore.yaml).\n"
    "\n"
    "La ressource clixz://overview est une synthèse à jour — services, "
    "exposition, audit, todo, plans en attente — à joindre à un projet."
)

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
PLAN = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False,
                       openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False,
                        openWorldHint=False)
DELETE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False,
                         openWorldHint=False)
# Écrit dans /srv/docker en root, et peut créer une stack dans Komodo.
APPLY = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False,
                        openWorldHint=True)

# ─── choix du mode d'authentification ───────────────────────────────────────
_OAUTH = oauth_config()
if _OAUTH:
    # Mode OAuth (Resource Server). Endpoint sur /mcp ; un 401 correct (avec
    # métadonnées) déclenche le flux OAuth côté client vers l'IdP.
    MCP_PATH = "/mcp"
    _AUTH_SETTINGS = AuthSettings(
        issuer_url=_OAUTH["issuer"],
        resource_server_url=_OAUTH["resource"],
        required_scopes=_OAUTH["required_scopes"] or None,
    )
    _VERIFIER = JWTVerifier(
        issuer=_OAUTH["issuer"],
        audience=_OAUTH["audience"],
        jwks_url=_OAUTH["jwks_url"],
        algorithms=_OAUTH["algorithms"],
        required_scopes=_OAUTH["required_scopes"],
    )
    mcp = FastMCP(
        "clixz",
        instructions=INSTRUCTIONS,
        host=HOST,
        port=PORT,
        stateless_http=True,
        streamable_http_path=MCP_PATH,
        token_verifier=_VERIFIER,
        auth=_AUTH_SETTINGS,
    )
else:
    # Mode chemin-secret (pas d'OAuth) : endpoint sur /<MCP_AUTH_TOKEN>/mcp.
    SECRET = os.environ.get("MCP_AUTH_TOKEN", "").strip()
    MCP_PATH = f"/{SECRET}/mcp" if SECRET else "/mcp"
    mcp = FastMCP(
        "clixz",
        instructions=INSTRUCTIONS,
        host=HOST,
        port=PORT,
        stateless_http=True,
        streamable_http_path=MCP_PATH,
    )


def _reader() -> ClixzReader:
    # Réinstancié à chaque appel pour toujours refléter l'état courant du disque.
    return ClixzReader(config_path=CONFIG_PATH, root_override=ROOT_OVERRIDE)


def _docs() -> DocsStore:
    return DocsStore(root=DOCS_ROOT, writable=DOCS_RW)


def _primary_image_ports(comp: dict, desc: dict):
    services = (comp or {}).get("services") or {}
    if not services:
        return None, []
    chosen = None
    for name, sdef in services.items():
        if sdef.get("container_name") == desc.get("container") or name == desc.get("key"):
            chosen = sdef
            break
    if chosen is None:
        chosen = next(iter(services.values()))
    ports = chosen.get("expose") or chosen.get("ports") or []
    return chosen.get("image"), ports


# ─── logique métier (réutilisée par tools + resources) ──────────────────────

def _list_categories() -> list[dict]:
    return _reader().categories()


def _list_services(category: str | None = None, public_only: bool = False) -> list[dict]:
    r = _reader()
    out: list[dict] = []
    for c, s, p in r.list_service_paths(category):
        d = r.descriptor(c, s, p)
        if public_only and not d.get("public"):
            continue
        img, ports = _primary_image_ports(r.compose(p), d)
        details = d.get("details") or {}
        out.append({
            "key": d["key"],
            "category": c,
            "name": d.get("name"),
            "icon": d.get("icon"),
            "kind": d.get("kind"),
            "public": d.get("public"),
            "url": d.get("url"),
            "image": img,
            "ports": ports,
            "tags": d.get("tags"),
            "summary": details.get("summary") or d.get("description"),
        })
    return out


def _get_service(service: str) -> dict:
    r = _reader()
    try:
        c, s, p = r.resolve(service)
    except ValueError as exc:
        return {"error": str(exc)}
    d = r.descriptor(c, s, p)
    d["compose"] = r.compose(p)
    return d


def _search_services(query: str) -> list[dict]:
    q = (query or "").lower().strip()
    if not q:
        return []
    r = _reader()
    out: list[dict] = []
    for c, s, p in r.list_service_paths():
        d = r.descriptor(c, s, p)
        det = d.get("details") or {}
        hay = " ".join(str(x) for x in [
            d.get("name"), d.get("description"), c, d.get("key"),
            " ".join(d.get("tags") or []), det.get("summary"), det.get("tech"),
        ] if x).lower()
        if q in hay:
            out.append({
                "key": d["key"], "category": c, "name": d.get("name"),
                "kind": d.get("kind"), "public": d.get("public"),
                "summary": det.get("summary") or d.get("description"),
            })
    return out


def _get_config() -> dict:
    r = _reader()
    if not r.raw:
        return {"error": f"config clixz illisible ou vide ({CONFIG_PATH})"}
    return {
        "config_path": str(r.config_path),
        "root_dir": str(r.root),
        "manifest_path": str(r.manifest_path),
        "config": r.raw,
    }


# ─── passerelle ──────────────────────────────────────────────────────────────

def _call(cmd: str, **params) -> dict:
    """Une requête à la passerelle ; une indisponibilité devient ``ok: false``."""
    try:
        return clixz_runner.run(cmd, **params)
    except (clixz_runner.RunnerUnavailable, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


def _cli(cmd: str, **params) -> dict:
    """Une lecture par la CLI, JSON décodé, ou ``{"error": …}``."""
    try:
        return clixz_runner.cli_json(cmd, **params)
    except (clixz_runner.RunnerUnavailable, ValueError) as exc:
        return {"error": str(exc)}


def _relayed(cmd: str, **params) -> dict:
    """Une requête relayée à clixz-apply : la réponse, sans ``ok``, ou l'erreur."""
    answer = _call(cmd, **params)
    if not answer.get("ok"):
        return {"error": answer.get("error") or "échec sans message"}
    return {k: v for k, v in answer.items() if k != "ok"}


# ─── outils : inventaire (lecture seule) ────────────────────────────────────

@mcp.tool(annotations=READ)
def categorie_list() -> list[dict]:
    """Liste les catégories de services déclarées et présentes sur le disque.

    Pour chacune : propriétaire/groupe système, nombre de services et noms des services.
    """
    return _list_categories()


@mcp.tool(annotations=READ)
def categorie_read(category: str) -> dict:
    """Détail d'une catégorie : compte système propriétaire, règles applicables, services.

    Croise la découverte disque avec la configuration de l'hôte, pour savoir
    sous quel compte tourne la catégorie et quel mode s'applique à chacun de
    ses types de chemin (`dir`, `file`, `env`).
    """
    for c in _list_categories():
        if c["name"] == category:
            r = _reader()
            rules = (r.raw.get("rules") or {}) if r.raw else {}
            return {**c, "rules": rules}
    known = ", ".join(c["name"] for c in _list_categories())
    return {"error": f"Catégorie inconnue : {category}. Connues : {known}."}


@mcp.tool(annotations=READ)
def service_list(category: str | None = None, public_only: bool = False) -> list[dict]:
    """Liste les services (résumé).

    - `category` : filtre optionnel (ex. "apps").
    - `public_only` : si vrai, ne renvoie que les services déclarés publics.

    Chaque entrée : key, category, name, kind, image, ports, public, url, tags, summary.
    """
    return _list_services(category, public_only)


@mcp.tool(annotations=READ)
def service_read(service: str) -> dict:
    """Détail complet d'un service.

    Renvoie le descripteur (service.yaml : name, description, kind, url, tags,
    details/summary/features/tech/ports) ET sa configuration docker non sensible
    (compose.yaml : image, expose/ports, volumes, réseaux, dépendances, limites,
    durcissement, et NOMS des variables d'environnement — valeurs masquées).

    Pour MODIFIER un service, relis d'abord ses fichiers ici, puis passe le
    fichier complet modifié à `service_update`.

    `service` : nom simple (ex. "grafana") ou "categorie/service" si ambigu.
    """
    return _get_service(service)


@mcp.tool(annotations=READ)
def service_search(query: str) -> list[dict]:
    """Recherche des services par mot-clé (nom, description, tags, techno, catégorie)."""
    return _search_services(query)


@mcp.tool(annotations=READ)
def boxyz_config() -> dict:
    """Configuration de `clixz` (/etc/clixz/config.yaml) — source de vérité de l'hôte.

    Donne les valeurs SPÉCIFIQUES à cet hôte, là où les documents de référence
    (voir `document_list`) décrivent les règles génériques :
    - `root_dir` et exclusions ;
    - `categories` : catégorie → compte/groupe système propriétaire ;
    - `rules` : mode octal par type de chemin — `dir`, `file`, `env` ;
    - emplacements `images`, `repos`, base `npm`, `state`, `komodo`.

    Ne contient aucun secret : des chemins, des noms de comptes, des modes.
    """
    return _get_config()


@mcp.tool(annotations=READ)
def service_check(service: str | None = None, verbose: bool = False) -> dict:
    """Audite l'infra : permissions de l'arborescence ET contenu des compose (`clixz check`).

    Répond à « est-ce que tout est bien configuré ? ». Deux volets, dans le
    JSON de `stdout` :
    - `findings` : dérives de permissions par rapport à /etc/clixz/config.yaml
      (propriétaire, mode octal, dossier ou fichier manquant). Ce sont elles qui
      rendent `exit_code` non nul.
    - `lint` : ce que clixz relève dans chaque compose.yaml (privileged, image
      en :latest, port publié sur toutes les interfaces, cap_drop absent…),
      avec le niveau `error` / `warn` / `info` et l'identifiant `rule`. Ce sont
      des avis : ils ne changent jamais `exit_code`.
    - `ignored` : les écarts que l'opérateur a acceptés dans ignore.yaml, avec
      leur raison. Ne les présente pas comme des problèmes.

    - `service` : limite l'audit à un service ("bitwarden" ou "apps/bitwarden").
    - `verbose` : inclut aussi les points conformes.

    LECTURE SEULE. Les permissions se corrigent avec `service_fix` (un plan),
    un compose avec `service_update` (un plan).
    """
    params: dict = {}
    if service:
        params["service"] = service
    if verbose:
        params["verbose"] = True
    return _call("check", **params)


@mcp.tool(annotations=READ)
def service_exposed() -> dict:
    """Ce que le reverse proxy publie RÉELLEMENT, croisé avec les service.yaml.

    À consulter avant toute affirmation sur ce qui est privé ou public : un
    service.yaml sans `url` ne prouve rien, l'exposition vit dans la base de
    Nginx Proxy Manager. Signale les hôtes publiés sans déclaration, les
    déclarations sans publication, les cibles mortes mais toujours activées,
    les wildcards et l'absence de liste d'accès.

    La base est lue au moment de l'appel (par `clixz-apply`, sur l'hôte). Si
    elle est illisible, `available` est faux et `reason` dit pourquoi — ne
    conclus alors rien.
    """
    return _relayed("exposed")


@mcp.tool(annotations=READ)
def boxyz_rules() -> dict:
    """Règles de compose EN VIGUEUR sur cet hôte, et écarts acceptés (`clixz rules`).

    - `rules` : chaque règle avec son identifiant, son niveau actuel
      (`error`, `warn`, `info`, `off`) et son niveau par défaut. Une règle en
      `error` non acceptée BLOQUE un plan.
    - `mounts` : les chemins hôte qu'un conteneur ne doit pas monter.
    - `ignore` : les écarts acceptés dans /etc/clixz/ignore.yaml — service,
      règles, raison.
    - `ignorable_only` : les constats de permissions, ignorables mais dont la
      gravité n'est pas réglable.

    À consulter avant de proposer un compose. Tu ne peux pas modifier ces
    fichiers ; si un écart mérite d'être accepté, propose à l'utilisateur
    l'entrée à ajouter à ignore.yaml (`sudo clixz rules --edit-ignore`).
    """
    return _cli("rules")


# ─── outils : plans de service ──────────────────────────────────────────────

_PLAN_KEYS = ("id", "action", "target", "status", "origin", "created_at", "expires_at",
              "commands", "diff", "lint", "warnings", "blocked")


def _plan_view(plan: dict) -> dict:
    """Le plan sans sa requête : le diff montre déjà les contenus."""
    return {k: plan.get(k) for k in _PLAN_KEYS}


def _service_plan(action: str, **params) -> dict:
    answer = _call("plan", action=action, **{k: v for k, v in params.items() if v is not None})
    if not answer.get("ok"):
        return {"error": answer.get("error") or "échec sans message"}
    plan = _plan_view(answer.get("plan") or {})
    if plan["blocked"]:
        plan["note"] = (
            "Plan REFUSÉ, rien n'est enregistré : voir `blocked`. Corrige le compose ou le "
            "service.yaml et redemande — ou, si l'écart est voulu, propose à l'utilisateur "
            "de l'accepter dans ignore.yaml, avec sa raison."
        )
    else:
        plan["note"] = (
            "Rien n'est écrit. Montre ce plan à l'utilisateur (diff, constats, avertissements). "
            f"S'il l'accepte explicitement, appelle plan_apply(plan_id=\"{plan['id']}\"). "
            f"Valable jusqu'à {plan['expires_at']} (UTC), une seule fois."
        )
    return plan


@mcp.tool(annotations=PLAN)
def service_create(service: str, compose: str | None = None, service_yaml: str | None = None,
                   stack: str | None = None) -> dict:
    """PRÉPARE la création d'un service : renvoie un PLAN, n'écrit rien.

    - `service` : "categorie/nom" (ex. "apps/mon-app" ; minuscules, chiffres, tirets).
    - `compose` : le compose.yaml complet. Absent : le gabarit durci de la
      catégorie (bonne base — demande-le d'abord pour partir de lui).
    - `service_yaml` : le descripteur (name, icon, description, public…). Absent :
      un gabarit commenté.
    - `stack` : nom de la stack Komodo (défaut : le nom du service).

    Le plan crée config/, data/, un .env VIDE (l'opérateur le remplit dans
    Komodo), les deux fichiers, et la stack dans Komodo — sans la déployer.
    Refusé (`blocked`) si le compose porte une erreur de lint non acceptée.
    Applique-le avec `plan_apply` après l'accord de l'utilisateur.
    """
    return _service_plan("new", service=service, compose=compose, service_yaml=service_yaml,
                         stack=stack)


@mcp.tool(annotations=PLAN)
def service_update(service: str, compose: str | None = None,
                   service_yaml: str | None = None) -> dict:
    """PRÉPARE la modification d'un service : renvoie un PLAN avec le diff, n'écrit rien.

    Remplace compose.yaml et/ou service.yaml par le contenu COMPLET fourni (pas
    un extrait : le fichier entier, tel qu'il doit être). Relis d'abord le
    service avec `service_read`. L'ancienne version est archivée à l'apply.

    Refusé (`blocked`) si rien ne change, si le compose porte une erreur de lint
    non acceptée, ou si le service.yaml est invalide. Le .env n'est pas
    modifiable ici. Applique avec `plan_apply` après l'accord de l'utilisateur ;
    le changement prend effet quand l'opérateur redéploie dans Komodo.
    """
    return _service_plan("edit", service=service, compose=compose, service_yaml=service_yaml)


@mcp.tool(annotations=PLAN)
def service_fix(service: str | None = None) -> dict:
    """PRÉPARE la correction des permissions : renvoie un PLAN, n'écrit rien.

    Répare propriétaire et mode sur l'arborescence d'un service (ou de tous si
    `service` est omis). Ne touche jamais au contenu de config/ ni de data/.
    Applique avec `plan_apply` après l'accord de l'utilisateur.
    """
    return _service_plan("fix", service=service)


@mcp.tool(annotations=PLAN)
def service_delete(service: str) -> dict:
    """PRÉPARE la suppression d'un service : renvoie un PLAN, n'écrit rien.

    La suppression est un ARCHIVAGE : l'arborescence est déplacée sous
    .archive/, jamais détruite, et reste récupérable — y compris `.env` et
    `data/`. La stack Komodo n'est pas touchée : l'opérateur l'arrête et la
    supprime dans Komodo. La destruction réelle n'est pas exprimable d'ici.
    """
    return _service_plan("rm", service=service)


@mcp.tool(annotations=READ)
def plan_list() -> dict:
    """Les plans enregistrés : en attente, et expirés depuis moins d'un jour.

    Pour chacun : id, action, target, status (pending, expired), origin,
    created_at, expires_at. Un plan oublié peut être supprimé (`plan_delete`).
    """
    return _relayed("plans")


@mcp.tool(annotations=READ)
def plan_read(plan_id: str) -> dict:
    """Un plan en détail : commandes, diff, constats du lint, avertissements."""
    answer = _relayed("plan-show", plan_id=plan_id)
    if "error" in answer:
        return answer
    return _plan_view(answer.get("plan") or {})


@mcp.tool(annotations=DELETE)
def plan_delete(plan_id: str) -> dict:
    """Supprime un plan en attente, sans l'appliquer."""
    return _relayed("plan-drop", plan_id=plan_id)


_AFTER_APPLY = {
    "new": "Le service est créé mais PAS déployé : dans Komodo, l'opérateur renseigne "
           "l'environnement de la stack puis la déploie.",
    "edit": "Les fichiers sont à jour, rien n'est redéployé : le changement prend effet quand "
            "l'opérateur redéploie la stack dans Komodo.",
    "fix": "Permissions corrigées.",
    "rm": "Le service est archivé. Sa stack Komodo reste : à arrêter et supprimer dans Komodo.",
}


@mcp.tool(annotations=APPLY)
def plan_apply(plan_id: str) -> dict:
    """APPLIQUE un plan — uniquement après l'accord EXPLICITE de l'utilisateur.

    Écrit sur l'hôte (en root, par clixz-apply) ce que le plan décrit. Le plan
    est recalculé d'abord : si le service a changé depuis, rien n'est écrit et
    il faut refaire le plan. Un plan s'applique une seule fois.

    Renvoie `ok`, les commandes exécutées, les échecs, les avertissements et
    les notes (dont la création de la stack Komodo). Rapporte-les fidèlement.
    """
    answer = _call("apply", plan_id=plan_id)
    if not answer.get("ok") and not answer.get("action"):
        return {"ok": False, "error": answer.get("error") or "échec sans message"}
    if answer.get("ok"):
        answer["next"] = _AFTER_APPLY.get(answer.get("action"), "")
    return answer


# ─── outils : todo ───────────────────────────────────────────────────────────

@mcp.tool(annotations=READ)
def todo_list(state: str | None = None, include_closed: bool = False) -> dict:
    """La todo de l'opérateur : ce qui reste à faire sur l'infrastructure.

    À consulter au début de toute conversation sur l'infra. Par défaut, les
    éléments ouverts (`todo`, `doing`) avec leur description.
    - `state` : seulement cet état (todo, doing, done, archived).
    - `include_closed` : aussi `done` et `archived`.
    """
    data = _cli("todo")
    if "error" in data:
        return data
    items = data.get("items") or []
    if state:
        items = [i for i in items if i.get("state") == state]
    elif not include_closed:
        items = [i for i in items if i.get("state") in ("todo", "doing")]
    return {"items": items, "count": len(items)}


@mcp.tool(annotations=READ)
def todo_read(id: int) -> dict:
    """Un élément de la todo, avec sa description complète."""
    return _cli("todo-show", id=id)


@mcp.tool(annotations=WRITE)
def todo_create(title: str, description: str = "", state: str = "todo") -> dict:
    """Ajoute un élément à la todo.

    - `title` : une ligne, 200 caractères au plus.
    - `description` : le détail (Markdown accepté) — le pourquoi, le comment.
    - `state` : todo (défaut), doing, done, archived.
    """
    return _relayed("todo-add", title=title, description=description, state=state)


@mcp.tool(annotations=WRITE)
def todo_update(id: int, title: str | None = None, description: str | None = None,
                state: str | None = None) -> dict:
    """Modifie un élément : titre, description (remplacée entière), état.

    États : todo, doing (en cours), done (fait), archived (gardé, hors des listes).
    """
    params = {k: v for k, v in (("title", title), ("description", description),
                                ("state", state)) if v is not None}
    return _relayed("todo-edit", id=id, **params)


@mcp.tool(annotations=DELETE)
def todo_delete(id: int) -> dict:
    """Supprime un élément pour de bon. Pour le garder hors des listes : state='archived'."""
    return _relayed("todo-rm", id=id)


# ─── outils : catégories et dépôts (plans à taper par l'opérateur) ─────────

def _named_plan(action: str, command: str, **params) -> dict:
    """Un plan de catégorie ou de dépôt : imprimé par la CLI, jamais appliqué d'ici."""
    result = _call("plan", action=action, **{k: v for k, v in params.items() if v})
    if isinstance(result, dict) and result.get("ok"):
        result["command_for_the_operator"] = command
        result["note"] = (
            "Rien n'a été écrit, et ce plan ne s'applique pas par plan_apply : "
            "donne cette commande à l'utilisateur, c'est lui qui l'exécute."
        )
    return result


@mcp.tool(annotations=PLAN)
def categorie_create(name: str, account: str | None = None) -> dict:
    """PRÉPARE la création d'une catégorie. N'écrit rien — renvoie un plan à taper.

    Une catégorie, c'est trois choses : un compte système qui la possède, un
    dossier sous /srv/docker, une entrée dans /etc/clixz/config.yaml.

    - `name` : minuscules, chiffres et tirets, commence par une lettre.
    - `account` : compte et groupe système propriétaires (défaut "svc_<name>").

    Renvoie les commandes, `next_steps` (dont `sudo clixz daemon install`, qui
    donne la catégorie à lire à la passerelle) et `command_for_the_operator`.
    """
    command = f"sudo clixz category add {name}"
    if account:
        command += f" --account {account}"
    return _named_plan("category-add", command, name=name, account=account)


@mcp.tool(annotations=READ)
def repo_list() -> dict:
    """Liste les dépôts git de /opt/repos (`clixz repo ls`).

    Pour chacun : name, path, git, branch et remote (l'URL d'origin,
    identifiants retirés). Dossiers de développement, séparés des services.
    """
    return _cli("repos")


@mcp.tool(annotations=PLAN)
def repo_create(name: str, url: str | None = None) -> dict:
    """PRÉPARE la création d'un dépôt sous /opt/repos. N'écrit rien — renvoie un plan à taper.

    - `name` : nom du dossier (lettres, chiffres, '.', '-', '_').
    - `url` : si fourni, le dépôt est CLONÉ (https://…, ssh://… ou git@hôte:chemin) ;
      sinon un dépôt vide est initialisé sur la branche main.
    """
    command = f"clixz repo add {name}"
    if url:
        command += f" --url {url}"
    return _named_plan("repo-add", command, name=name, url=url)


@mcp.tool(annotations=PLAN)
def repo_delete(name: str) -> dict:
    """PRÉPARE la suppression d'un dépôt de /opt/repos. N'écrit rien — renvoie un plan à taper.

    Contrairement à `service_delete`, ce n'est PAS un archivage : le dossier
    est supprimé, et les commits non poussés sont perdus. Dis-le à l'utilisateur.
    """
    return _named_plan("repo-rm", f"clixz repo rm {name}", name=name)


# ─── outils : documentation (/srv/docs) ─────────────────────────────────────

@mcp.tool(annotations=READ)
def document_list(category: str | None = None) -> list[dict]:
    """Liste les documents de référence (règles et conventions de l'infra).

    Ces documents décrivent les RÈGLES à respecter (compose, réseau,
    permissions, durcissement) — consulte-les avant de proposer une
    configuration. Ils ne contiennent pas l'inventaire des services.

    - `category` : filtre optionnel sur le sous-dossier (ex. "conventions").

    Chaque entrée : doc ("catégorie/nom.md"), category, name, title, headings
    (plan de niveau 2), bytes, modified. Le contenu s'obtient via `document_read`.
    """
    try:
        return _docs().list(category)
    except DocsError as exc:
        return [{"error": str(exc)}]


@mcp.tool(annotations=READ)
def document_read(doc: str) -> dict:
    """Contenu Markdown intégral d'un document de référence.

    `doc` : "catégorie/nom.md" (ex. "conventions/network-ports.md") ou nom
    simple s'il est unique (ex. "network-ports").
    """
    try:
        return _docs().get(doc)
    except DocsError as exc:
        return {"error": str(exc)}
    except OSError as exc:
        return {"error": f"Lecture impossible : {exc}"}


@mcp.tool(annotations=WRITE)
def document_create(category: str, name: str, content: str) -> dict:
    """Crée un NOUVEAU document de référence Markdown.

    Échoue si le document existe déjà — utilise alors `document_update`.

    - `category` : sous-dossier (ex. "conventions"). Créé s'il n'existe pas.
    - `name` : nom de fichier (".md" ajouté si absent). Lettres, chiffres,
      '.', '-', '_' uniquement.
    - `content` : Markdown complet, commençant idéalement par un titre `# `.
    """
    try:
        return _docs().create(category, name, content)
    except DocsError as exc:
        return {"error": str(exc)}
    except OSError as exc:
        return {"error": f"Écriture impossible : {exc}"}


@mcp.tool(annotations=WRITE)
def document_update(doc: str, content: str, mode: str = "replace") -> dict:
    """Met à jour un document de référence EXISTANT.

    La version précédente est conservée à côté en `.bak`.

    - `doc` : "catégorie/nom.md" ou nom simple s'il est unique.
    - `content` : en mode "replace" (défaut), remplace TOUT le document — passe
      donc le texte complet ; en mode "append", le texte est ajouté à la fin.
    - `mode` : "replace" ou "append".
    """
    try:
        return _docs().update(doc, content, mode)
    except DocsError as exc:
        return {"error": str(exc)}
    except OSError as exc:
        return {"error": f"Écriture impossible : {exc}"}


@mcp.tool(annotations=DELETE)
def document_delete(doc: str) -> dict:
    """Supprime un document de référence (en réalité : l'archive, jamais ne le détruit).

    `doc` : "catégorie/nom.md" ou nom simple s'il est unique. Les catégories
    qui portent les règles (conventions, hardening) sont en lecture seule.
    """
    try:
        return _docs().delete(doc)
    except DocsError as exc:
        return {"error": str(exc)}
    except OSError as exc:
        return {"error": f"Suppression impossible : {exc}"}


# ─── ressources MCP ─────────────────────────────────────────────────────────

def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _todo_markdown(items: list[dict], *, heading: str = "") -> str:
    if not items:
        return "Rien à faire.\n"
    out = []
    for item in items:
        state = "en cours" if item.get("state") == "doing" else "à faire"
        out.append(f"{heading}## #{item.get('id')} {item.get('title')} — {state}\n")
        if item.get("description"):
            out.append(f"{item['description'].strip()}\n")
    return "\n".join(out)


def _open_todo() -> list[dict] | str:
    data = _cli("todo")
    if "error" in data:
        return f"_todo illisible : {data['error']}_"
    return [i for i in data.get("items") or [] if i.get("state") in ("todo", "doing")]


def _overview() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [f"# Boxyz — état de l'infrastructure\n\n_Généré le {now} par le serveur MCP clixz._\n"]

    parts.append("## À faire\n")
    todo = _open_todo()
    parts.append(todo if isinstance(todo, str) else _todo_markdown(todo, heading="#"))

    plans = _relayed("plans")
    parts.append("## Plans en attente\n")
    if "error" in plans:
        parts.append(f"_indisponible : {plans['error']}_\n")
    else:
        pending = [p for p in plans.get("plans") or [] if p.get("status") == "pending"]
        parts.append("\n".join(f"- `{p['id']}` {p['action']} {p['target']} "
                               f"(expire {p['expires_at']})" for p in pending) or "Aucun.")
        parts.append("")

    services = _list_services()
    parts.append(f"## Services ({len(services)})\n")
    parts.append("| Service | Image | URL | Public |\n|---|---|---|---|")
    for svc in services:
        parts.append(f"| {svc['category']}/{svc['key']} | {svc.get('image') or '—'} | "
                     f"{svc.get('url') or '—'} | {'oui' if svc.get('public') else 'non'} |")
    parts.append("")

    exposed = _relayed("exposed")
    parts.append("## Exposition Internet\n")
    if "error" in exposed or not exposed.get("available"):
        parts.append(f"_indisponible : {exposed.get('error') or exposed.get('reason')}_\n")
    else:
        summary = exposed.get("summary") or {}
        parts.append(f"{summary.get('total')} hôte(s) dans le reverse proxy, "
                     f"{summary.get('enabled')} activé(s).\n")
        for host in exposed.get("hosts") or []:
            if host.get("enabled"):
                access = "liste d'accès" if host.get("access_list_id") else "ouvert"
                parts.append(f"- {', '.join(host.get('domains') or [])} → {host.get('target')} "
                             f"({access})")
        findings = [f for f in exposed.get("findings") or [] if f.get("level") != "info"]
        if findings:
            parts.append("\nConstats :")
            parts += [f"- {f['level']} : {f['message']}" for f in findings]
        parts.append("")

    check = _cli("check")
    parts.append("## Audit (`clixz check`)\n")
    if "error" in check:
        parts.append(f"_indisponible : {check['error']}_\n")
    else:
        s = check.get("summary") or {}
        parts.append(f"Permissions : {s.get('errors', 0)} erreur(s), {s.get('warnings', 0)} "
                     f"avertissement(s). Compose : {s.get('lint_errors', 0)} erreur(s), "
                     f"{s.get('lint_warnings', 0)} avertissement(s), {s.get('lint_infos', 0)} "
                     f"info(s). Écarts acceptés : {s.get('ignored', 0)}.\n")
        flagged = [svc["name"] for svc in check.get("services") or []
                   if svc.get("severity") == "error"
                   or any(x.get("level") == "error" for x in svc.get("lint") or [])]
        if flagged:
            parts.append("Avec au moins une erreur : " + ", ".join(flagged) + "\n")
    return "\n".join(parts)


@mcp.resource("clixz://overview", mime_type="text/markdown")
def res_overview() -> str:
    """Synthèse à jour de l'infrastructure (Markdown) : todo, plans, services, exposition, audit."""
    return _overview()


@mcp.resource("clixz://todo", mime_type="text/markdown")
def res_todo() -> str:
    """La todo ouverte de l'opérateur (Markdown)."""
    todo = _open_todo()
    return "# À faire\n\n" + (todo if isinstance(todo, str) else _todo_markdown(todo))


@mcp.resource("clixz://plans", mime_type="application/json")
def res_plans() -> str:
    """Les plans enregistrés, en attente ou expirés depuis moins d'un jour (JSON)."""
    return _json(_relayed("plans"))


@mcp.resource("clixz://rules", mime_type="application/json")
def res_rules() -> str:
    """Règles de compose en vigueur et écarts acceptés (JSON)."""
    return _json(_cli("rules"))


@mcp.resource("clixz://exposed", mime_type="application/json")
def res_exposed() -> str:
    """Ce que le reverse proxy publie, lu en direct (JSON)."""
    return _json(_relayed("exposed"))


@mcp.resource("clixz://check", mime_type="application/json")
def res_check() -> str:
    """L'audit complet : permissions, lint des compose, écarts acceptés (JSON)."""
    return _json(_cli("check"))


@mcp.resource("clixz://categories", mime_type="application/json")
def res_categories() -> str:
    """Catégories de l'infrastructure (JSON)."""
    return _json(_list_categories())


@mcp.resource("clixz://services", mime_type="application/json")
def res_services() -> str:
    """Tous les services avec leur résumé (JSON)."""
    return _json(_list_services())


@mcp.resource("clixz://service/{name}", mime_type="application/json")
def res_service(name: str) -> str:
    """Détail complet d'un service (JSON)."""
    return _json(_get_service(name))


@mcp.resource("clixz://config", mime_type="application/json")
def res_config() -> str:
    """Configuration de clixz pour cet hôte (JSON)."""
    return _json(_get_config())


@mcp.resource("clixz://docs", mime_type="application/json")
def res_docs() -> str:
    """Index des documents de référence (JSON)."""
    return _json(_docs().list())


@mcp.resource("clixz://doc/{name}", mime_type="text/markdown")
def res_doc(name: str) -> str:
    """Contenu Markdown d'un document de référence."""
    try:
        return _docs().get(name)["content"]
    except (DocsError, OSError) as exc:
        return f"# Erreur\n\n{exc}\n"


# ─── santé : /healthz ouvert (pour le healthcheck / reverse proxy) ──────────
# Volontairement AUCUNE authentification par 401 ici : un 401 sans métadonnées
# OAuth fait échouer les connecteurs Claude (web/Code). La protection repose sur
# OAuth (ou le secret de chemin) pour /mcp ; /healthz ne dit que « ok ».

class HealthMiddleware:
    """Middleware ASGI : répond 200 sur /healthz, laisse passer le reste."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path", "") in ("/healthz", "/health"):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")],
            })
            await send({"type": "http.response.body", "body": b"ok"})
            return
        await self.app(scope, receive, send)


def build_app():
    app = mcp.streamable_http_app()
    app.add_middleware(HealthMiddleware)
    return app


def main() -> None:
    import uvicorn

    if _OAUTH:
        print(
            f"[clixz-mcp] mode OAuth (Resource Server) — IdP {_OAUTH['issuer']} "
            f"audience {_OAUTH['audience']}",
            flush=True,
        )
    else:
        secret = os.environ.get("MCP_AUTH_TOKEN", "").strip()
        if secret:
            print("[clixz-mcp] mode chemin secret", flush=True)
        else:
            print(
                "[clixz-mcp] ATTENTION : ni OAuth ni MCP_AUTH_TOKEN — endpoint OUVERT "
                "sur /mcp. À éviter en exposition publique.",
                flush=True,
            )
    print(
        f"[clixz-mcp] docs {DOCS_ROOT} — "
        f"{'LECTURE/ÉCRITURE' if DOCS_RW else 'lecture seule'}",
        flush=True,
    )
    print(
        f"[clixz-mcp] passerelle clixz {clixz_runner.SOCKET_PATH} — "
        f"{'disponible' if clixz_runner.available() else 'ABSENTE (outils clixz inactifs)'}",
        flush=True,
    )
    print(f"[clixz-mcp] écoute http://{HOST}:{PORT}{MCP_PATH} (config={CONFIG_PATH})", flush=True)
    uvicorn.run(build_app(), host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
