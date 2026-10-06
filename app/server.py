"""Serveur MCP pour l'infrastructure Docker Boxyz, gérée par la CLI `clixz`.

Expose aux assistants IA, via le Model Context Protocol :
- les catégories de services ;
- la liste des services et leur résumé ;
- la configuration NON sensible d'un service (service.yaml + compose.yaml) ;
- l'audit des permissions et des compose, et l'exposition réelle par le proxy ;
- les règles de compose en vigueur et les écarts acceptés ;
- les dépôts git de /opt/repos ;
- les documents de référence (/srv/docs) décrivant les règles et conventions.

L'inventaire des services reste en **lecture seule stricte**, et aucun secret
(.env) n'est accessible. Toute mutation (service, catégorie, dépôt) est rendue
sous forme de PLAN : rien n'est écrit, c'est l'humain qui exécute. Seuls les
documents de /srv/docs peuvent être créés ou modifiés, et uniquement si
CLIXZ_DOCS_RW est activé. Transport HTTP
« streamable-http », destiné à être placé derrière le reverse proxy.

Authentification — deux modes :
  • OAuth (si OAUTH_ISSUER défini) : le serveur agit en Resource Server, publie
    les métadonnées OAuth pointant vers l'IdP (Auth0), et valide les JWT émis par
    lui. C'est l'IdP qui gère login/consentement. Endpoint sur /mcp.
  • Chemin secret (sinon) : endpoint servi sur /<MCP_AUTH_TOKEN>/mcp (ou /mcp si
    vide). Aucun 401 → pas de bascule OAuth. Utile pour tester en local.

Variables d'environnement :
  MCP_HOST / MCP_PORT      (def. 0.0.0.0 / 8000)
  CLIXZ_CONFIG / CLIXZ_ROOT   (COXYZ_* encore accepté)
  MCP_AUTH_TOKEN           secret de chemin (mode non-OAuth uniquement)
  OAUTH_ISSUER / OAUTH_AUDIENCE / OAUTH_RESOURCE_URL / OAUTH_REQUIRED_SCOPES
                           voir auth.py (active le mode OAuth)
  CLIXZ_DOCS               racine des documents de référence (def. /srv/docs)
  CLIXZ_DOCS_RW            "1" pour autoriser document_create/update (def. non)
"""

from __future__ import annotations

import json
import os

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

import compat
import clixz_runner
from auth import JWTVerifier, oauth_config
from clixz_reader import ClixzReader
from docs_store import DocsError, DocsStore

CONFIG_PATH = compat.env("CONFIG") or compat.first_existing(
    "/etc/clixz/config.yaml", "/etc/coxyz/config.yaml"
)
ROOT_OVERRIDE = compat.env("ROOT") or None
HOST = os.environ.get("MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("MCP_PORT", "8000"))
DOCS_ROOT = compat.env("DOCS", "/srv/docs")
DOCS_RW = compat.env("DOCS_RW") not in ("", "0", "false", "False")

INSTRUCTIONS = (
    "Serveur MCP pour l'infrastructure Docker Boxyz (gérée par la CLI `clixz` "
    "2.x, root_dir /srv/docker). Les outils sont groupés par préfixe :\n"
    "\n"
    "• service_* — INVENTAIRE. service_list, service_read et service_search "
    "lisent service.yaml et compose.yaml ; aucun secret n'est exposé (seuls les "
    "NOMS des variables d'environnement, jamais leurs valeurs). service_check "
    "audite les permissions ET analyse les compose.yaml : il signale, il ne "
    "corrige rien. service_exposed compare ce que le reverse proxy publie "
    "réellement à ce que déclarent les service.yaml — c'est le seul outil qui "
    "voit l'exposition Internet, regarde-le avant de conclure qu'un service est "
    "privé ; il lit une copie de la base du proxy rafraîchie périodiquement, "
    "et indique son âge.\n"
    "  MUTATIONS — service_create, service_fix et service_delete N'ÉCRIVENT "
    "RIEN et ne le peuvent pas : la passerelle est non privilégiée et l'arbre "
    "est monté en lecture seule. Ils renvoient un PLAN et la commande exacte à "
    "exécuter. Présente le plan à l'utilisateur et donne-lui la commande : "
    "c'est LUI qui l'exécute au clavier, avec sudo. N'affirme jamais qu'une "
    "modification est faite — tu ne peux pas la faire.\n"
    "  Le compose.yaml est écrit à la main et fait autorité. Tu peux en "
    "proposer un ; dis clairement à l'utilisateur où le coller, puis fais-lui "
    "lancer service_check pour le relire. Le durcissement attendu : "
    "cap_drop ALL, no-new-privileges, user: non root, restart, rotation des "
    "logs, image épinglée (jamais :latest), ports en 127.0.0.1: sauf besoin LAN "
    "explicite. Ces attentes sont des RÈGLES à identifiant, dont le niveau "
    "est fixé par l'opérateur : boxyz_rules donne les règles en vigueur et les "
    "écarts qu'il a acceptés, service par service, avec leur raison. Ne "
    "présente pas comme un problème un écart déjà accepté.\n"
    "\n"
    "• categorie_* — les catégories et leur compte système propriétaire. Ce "
    "cloisonnement protège les conteneurs NON root les uns des autres ; un "
    "conteneur root le contourne par construction. categorie_create PRÉPARE "
    "une nouvelle catégorie (compte système, dossier, entrée de config) : "
    "c'est un plan, comme toute mutation.\n"
    "\n"
    "• repo_* — les dépôts git de /opt/repos (code source, séparé des "
    "services). repo_list les énumère avec leur branche et leur remote ; "
    "repo_create et repo_delete renvoient un plan.\n"
    "\n"
    "• document_* — DOCUMENTATION (/srv/docs) : les règles et conventions. "
    "Consulte-les AVANT de proposer une configuration. document_list donne le "
    "plan de chaque document sans son contenu. IMPORTANT : les catégories "
    "'conventions' et 'hardening' sont en LECTURE SEULE — ce sont les règles "
    "qui te contraignent, tu ne peux pas les réécrire pour t'autoriser autre "
    "chose. Si une règle te paraît fausse, signale-le à l'utilisateur. Les "
    "autres catégories sont modifiables, et document_delete archive au lieu de "
    "détruire.\n"
    "\n"
    "• boxyz_* — configuration propre à cet hôte. boxyz_config lit "
    "/etc/clixz/config.yaml (comptes par catégorie, modes par type de chemin) ; "
    "boxyz_rules lit lint.yaml et ignore.yaml (niveau de chaque règle de "
    "compose, écarts acceptés). C'est la source de vérité des valeurs locales, "
    "là où la documentation donne les règles génériques."
)

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
        "coxyz-infra",
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
        "coxyz-infra",
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


def _get_coxyz_config() -> dict:
    r = _reader()
    if not r.raw:
        return {"error": f"config clixz illisible ou vide ({CONFIG_PATH})"}
    return {
        "config_path": str(r.config_path),
        "root_dir": str(r.root),
        "manifest_path": str(r.manifest_path),
        "config": r.raw,
    }


# ─── outils MCP (lecture seule) ─────────────────────────────────────────────

@mcp.tool()
def categorie_list() -> list[dict]:
    """Liste les catégories de services déclarées et présentes sur le disque.

    Pour chacune : propriétaire/groupe système, nombre de services et noms des services.
    """
    return _list_categories()


@mcp.tool()
def categorie_read(category: str) -> dict:
    """Détail d'une catégorie : compte système propriétaire, règles applicables, services.

    Croise la découverte disque avec la configuration de l'hôte, pour savoir
    sous quel compte tourne la catégorie et quel mode s'applique à chacun de
    ses types de chemin (`dir`, `file`, `env`). clixz 2.x n'utilise plus d'ACL.
    """
    for c in _list_categories():
        if c["name"] == category:
            r = _reader()
            rules = (r.raw.get("rules") or {}) if r.raw else {}
            return {**c, "rules": rules}
    known = ", ".join(c["name"] for c in _list_categories())
    return {"error": f"Catégorie inconnue : {category}. Connues : {known}."}


@mcp.tool()
def service_list(category: str | None = None, public_only: bool = False) -> list[dict]:
    """Liste les services (résumé).

    - `category` : filtre optionnel (ex. "apps").
    - `public_only` : si vrai, ne renvoie que les services exposés publiquement.

    Chaque entrée : key, category, name, kind, image, ports, public, url, tags, summary.
    """
    return _list_services(category, public_only)


@mcp.tool()
def service_read(service: str) -> dict:
    """Détail complet d'un service.

    Renvoie le descripteur (service.yaml : name, description, kind, url, tags,
    details/summary/features/tech/ports) ET sa configuration docker non sensible
    (compose.yaml : image, expose/ports, volumes, réseaux, dépendances, limites,
    durcissement, et NOMS des variables d'environnement — valeurs masquées).

    `service` : nom simple (ex. "grafana") ou "categorie/service" si ambigu.
    """
    return _get_service(service)


@mcp.tool()
def service_search(query: str) -> list[dict]:
    """Recherche des services par mot-clé (nom, description, tags, techno, catégorie)."""
    return _search_services(query)


@mcp.tool()
def boxyz_config() -> dict:
    """Configuration de `clixz` (/etc/clixz/config.yaml) — source de vérité de l'hôte.

    Donne les valeurs SPÉCIFIQUES à cet hôte, là où les documents de référence
    (voir `document_list`) décrivent les règles génériques :
    - `root_dir` et exclusions ;
    - `categories` : catégorie → compte/groupe système propriétaire ;
    - `rules` : mode octal par type de chemin — `dir` (750), `file` (640),
      `env` (600, root:root). clixz 2.x n'utilise plus d'ACL POSIX ;
    - emplacements `images`, `repos`, base `npm`.

    Les règles de compose et les écarts acceptés ne sont pas ici : voir
    `boxyz_rules`.

    Ne contient aucun secret : ce sont des chemins, des noms de comptes et des
    modes de permission.
    """
    return _get_coxyz_config()


# ─── outils commandes clixz (lecture seule, via la passerelle) ──────────────

def _runner(cmd: str, **params) -> dict:
    try:
        return clixz_runner.run(cmd, **params)
    except clixz_runner.RunnerUnavailable as exc:
        return {"error": str(exc)}
    except ValueError as exc:
        return {"error": str(exc)}


@mcp.tool()
def service_check(service: str | None = None, verbose: bool = False) -> dict:
    """Audite l'infra : permissions de l'arborescence ET contenu des compose (`clixz check`).

    Répond à « est-ce que tout est bien configuré ? ». Deux volets, dans le
    JSON de `stdout` :
    - `findings` : dérives de permissions par rapport à /etc/clixz/config.yaml
      (propriétaire, mode octal, dossier ou fichier manquant, ACL restée de la
      v1). Ce sont elles qui rendent `exit_code` non nul.
    - `lint` : ce que clixz relève dans chaque compose.yaml (privileged, image
      en :latest, port publié sur toutes les interfaces, cap_drop absent…),
      avec le niveau `error` / `warn` / `info` et l'identifiant `rule`. Ce sont
      des avis : ils ne changent jamais `exit_code`.
    - `ignored` : les écarts que l'opérateur a acceptés dans ignore.yaml, avec
      leur raison. Ne les présente pas comme des problèmes.

    - `service` : limite l'audit à un service ("bitwarden" ou "apps/bitwarden").
      Par défaut, tout est audité.
    - `verbose` : inclut aussi les points conformes, pas seulement les dérives.

    LECTURE SEULE : rien n'est corrigé. `exit_code` non nul signale une dérive
    détectée, pas un échec d'exécution. Les permissions se corrigent avec
    `service_fix` (qui renvoie un plan) ; un compose se corrige à la main.
    """
    params: dict = {}
    if service:
        params["service"] = service
    if verbose:
        params["verbose"] = True
    return _runner("check", **params)



def _plan(action: str, command: str, **params) -> dict:
    """Demande un plan à la passerelle et y joint la commande pour l'humain.

    La passerelle transmet le verbe à la CLI avec ``--plan`` : elle imprime ce
    qu'elle ferait et n'écrit rien. Il n'existe pas d'`apply` distant — c'est
    délibéré : le serveur MCP est joignable par le réseau, l'exécution ne doit
    pas l'être.

    `command` est la ligne que l'humain tapera ; elle est jointe au résultat
    pour que l'assistant n'ait pas à la reconstituer.
    """
    result = _runner("plan", action=action, **{k: v for k, v in params.items() if v})
    if isinstance(result, dict) and "error" not in result:
        result["command_for_the_operator"] = command
        result["note"] = (
            "Rien n'a été écrit. Donne cette commande à l'utilisateur ; "
            "c'est lui qui l'exécute."
        )
    return result


@mcp.tool()
def service_exposed() -> dict:
    """Ce que le reverse proxy publie RÉELLEMENT, croisé avec les service.yaml.

    À consulter avant toute affirmation sur ce qui est privé ou public : un
    service.yaml sans `url` ne prouve rien, l'exposition vit dans la base de
    Nginx Proxy Manager. Signale les hôtes publiés sans déclaration, les
    déclarations sans publication, les cibles mortes mais toujours activées,
    les wildcards et l'absence de liste d'accès.

    La base du proxy n'est lisible que par root, et la passerelle ne l'est
    pas : la réponse vient d'une COPIE que root rafraîchit périodiquement
    (`source: "snapshot"`, datée par `snapshot_at`). Tiens compte de son âge
    si l'utilisateur vient de modifier le proxy. Si la copie n'existe pas,
    `available` est faux et `reason` dit quoi lancer — ne conclus alors rien.
    """
    return _runner("exposed")


@mcp.tool()
def boxyz_rules() -> dict:
    """Règles de compose EN VIGUEUR sur cet hôte, et écarts acceptés (`clixz rules`).

    - `rules` : chaque règle avec son identifiant, son niveau actuel
      (`error`, `warn`, `info`, `off`) et son niveau par défaut. L'opérateur
      règle ces niveaux dans /etc/clixz/lint.yaml.
    - `mounts` : les chemins hôte qu'un conteneur ne doit pas monter.
    - `ignore` : les écarts acceptés dans /etc/clixz/ignore.yaml — service,
      règles, raison.
    - `ignorable_only` : les constats de permissions, ignorables mais dont la
      gravité n'est pas réglable.

    À consulter avant de proposer un compose ou de commenter un audit : c'est
    ce fichier, pas une règle générale, qui dit ce que cet hôte considère
    comme un problème. Tu ne peux pas le modifier ; si un écart mérite d'être
    accepté, propose à l'utilisateur l'entrée à ajouter à ignore.yaml
    (`sudo clixz rules --edit-ignore`), avec sa raison.
    """
    return _runner("rules")


@mcp.tool()
def service_create(service: str) -> dict:
    """PRÉPARE la création d'un service. N'écrit rien — renvoie un plan.

    `service` : "categorie/nom" (ex. "apps/mon-app").

    clixz crée l'arborescence (config/, data/, .env, service.yaml) et un
    compose.yaml pré-rempli, durci, que l'utilisateur édite ensuite. Renvoie la
    liste des commandes et `command_for_the_operator` : donne-la-lui, c'est lui
    qui l'exécute.
    """
    return _plan("new", f"sudo clixz new {service}", service=service)


@mcp.tool()
def service_fix(service: str | None = None) -> dict:
    """PRÉPARE la correction des permissions. N'écrit rien — renvoie un plan.

    Répare propriétaire et mode sur l'arborescence d'un service (ou de tous si
    `service` est omis). Ne touche jamais au contenu de config/ ni de data/.
    Renvoie les commandes et `command_for_the_operator`.
    """
    return _plan("fix", f"sudo clixz fix {service or ''}".strip(), service=service)


@mcp.tool()
def service_delete(service: str) -> dict:
    """PRÉPARE la suppression d'un service. N'écrit rien — renvoie un plan.

    La suppression est un ARCHIVAGE : l'arborescence est déplacée sous
    .archive/, jamais détruite, et reste récupérable — y compris `.env` et
    `data/`. La destruction réelle (`--force`) n'est pas exprimable depuis ce
    serveur, uniquement depuis un terminal.
    """
    return _plan("rm", f"sudo clixz rm {service}", service=service)


# ─── catégories et dépôts (plans uniquement) ────────────────────────────────

@mcp.tool()
def categorie_create(name: str, account: str | None = None) -> dict:
    """PRÉPARE la création d'une catégorie. N'écrit rien — renvoie un plan.

    Une catégorie, c'est trois choses : un compte système qui la possède, un
    dossier sous /srv/docker, une entrée dans /etc/clixz/config.yaml.

    - `name` : minuscules, chiffres et tirets, commence par une lettre
      (ex. "media").
    - `account` : compte et groupe système propriétaires. Par défaut
      "svc_<name>", créé s'il n'existe pas.

    Renvoie les commandes, `next_steps` (deux gestes manuels pour que la
    passerelle et ce serveur puissent LIRE la nouvelle catégorie : tant qu'ils
    ne sont pas faits, elle n'apparaîtra pas ici) et `command_for_the_operator`.
    """
    command = f"sudo clixz category add {name}"
    if account:
        command += f" --account {account}"
    return _plan("category-add", command, name=name, account=account)


@mcp.tool()
def repo_list() -> dict:
    """Liste les dépôts git de /opt/repos (`clixz repo ls`).

    Pour chacun : name, path, git (faux si le dossier n'est pas un dépôt),
    branch et remote (l'URL d'origin, identifiants retirés). Ce sont des
    dossiers de développement, séparés des services de /srv/docker ; clixz
    n'audite pas leurs permissions.
    """
    return _runner("repos")


@mcp.tool()
def repo_create(name: str, url: str | None = None) -> dict:
    """PRÉPARE la création d'un dépôt sous /opt/repos. N'écrit rien — renvoie un plan.

    - `name` : nom du dossier (lettres, chiffres, '.', '-', '_').
    - `url` : si fourni, le dépôt est CLONÉ depuis ce remote (https://…,
      ssh://… ou git@hôte:chemin) ; sinon un dépôt vide est initialisé sur la
      branche main.

    Pas de sudo : la commande se lance avec le compte de l'utilisateur.
    """
    command = f"clixz repo add {name}"
    if url:
        command += f" --url {url}"
    return _plan("repo-add", command, name=name, url=url)


@mcp.tool()
def repo_delete(name: str) -> dict:
    """PRÉPARE la suppression d'un dépôt de /opt/repos. N'écrit rien — renvoie un plan.

    Contrairement à `service_delete`, ce n'est PAS un archivage : le dossier
    est supprimé, et les commits non poussés sont perdus. Dis-le à
    l'utilisateur en lui donnant la commande.
    """
    return _plan("repo-rm", f"clixz repo rm {name}", name=name)


# ─── outils documentation (/srv/docs) ───────────────────────────────────────

@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
def document_update(doc: str, content: str, mode: str = "replace") -> dict:
    """Met à jour un document de référence EXISTANT.

    La version précédente est conservée à côté en `.bak`.

    - `doc` : "catégorie/nom.md" ou nom simple s'il est unique.
    - `content` : en mode "replace" (défaut), remplace TOUT le document — passe
      donc le texte complet, pas seulement la partie modifiée ; en mode
      "append", le texte est ajouté à la fin.
    - `mode` : "replace" ou "append".
    """
    try:
        return _docs().update(doc, content, mode)
    except DocsError as exc:
        return {"error": str(exc)}
    except OSError as exc:
        return {"error": f"Écriture impossible : {exc}"}


@mcp.tool()
def document_delete(doc: str) -> dict:
    """Supprime un document de référence.

    `doc` : "catégorie/nom.md" ou nom simple s'il est unique.

    Le document disparaît de `document_list` et de `document_read`. Sur le
    disque il est en réalité archivé, jamais détruit : rien n'est perdu si la
    suppression était une erreur. Les catégories qui portent les règles
    (conventions, hardening) sont en lecture seule et refuseront l'opération.
    """
    try:
        return _docs().delete(doc)
    except DocsError as exc:
        return {"error": str(exc)}
    except OSError as exc:
        return {"error": f"Suppression impossible : {exc}"}


# ─── ressources MCP ─────────────────────────────────────────────────────────

@mcp.resource("coxyz://categories")
def res_categories() -> str:
    """Catégories de l'infrastructure (JSON)."""
    return json.dumps(_list_categories(), ensure_ascii=False, indent=2)


@mcp.resource("coxyz://services")
def res_services() -> str:
    """Tous les services avec leur résumé (JSON)."""
    return json.dumps(_list_services(), ensure_ascii=False, indent=2)


@mcp.resource("coxyz://service/{name}")
def res_service(name: str) -> str:
    """Détail complet d'un service (JSON)."""
    return json.dumps(_get_service(name), ensure_ascii=False, indent=2)


@mcp.resource("coxyz://config")
def res_config() -> str:
    """Configuration de clixz pour cet hôte (JSON)."""
    return json.dumps(_get_coxyz_config(), ensure_ascii=False, indent=2)


@mcp.resource("coxyz://docs")
def res_docs() -> str:
    """Index des documents de référence (JSON)."""
    return json.dumps(_docs().list(), ensure_ascii=False, indent=2)


@mcp.resource("coxyz://doc/{name}")
def res_doc(name: str) -> str:
    """Contenu Markdown d'un document de référence."""
    try:
        return _docs().get(name)["content"]
    except (DocsError, OSError) as exc:
        return f"# Erreur\n\n{exc}\n"


# ─── santé : /healthz ouvert (pour le healthcheck / reverse proxy) ──────────
# Volontairement AUCUNE authentification par 401 ici : un 401 sans métadonnées
# OAuth fait échouer les connecteurs Claude (web/Code). La protection repose sur
# le secret de chemin (URL indevinable) + le caractère non sensible des données.

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
            f"[coxyz-mcp] mode OAuth (Resource Server) — IdP {_OAUTH['issuer']} "
            f"audience {_OAUTH['audience']}",
            flush=True,
        )
    else:
        secret = os.environ.get("MCP_AUTH_TOKEN", "").strip()
        if secret:
            print(f"[coxyz-mcp] mode chemin secret : {MCP_PATH}", flush=True)
        else:
            print(
                "[coxyz-mcp] ATTENTION : ni OAuth ni MCP_AUTH_TOKEN — endpoint OUVERT "
                "sur /mcp. À éviter en exposition publique.",
                flush=True,
            )
    print(
        f"[coxyz-mcp] docs {DOCS_ROOT} — "
        f"{'LECTURE/ÉCRITURE' if DOCS_RW else 'lecture seule'}",
        flush=True,
    )
    print(
        f"[boxyz-mcp] passerelle clixz {clixz_runner.SOCKET_PATH} — "
        f"{'disponible' if clixz_runner.available() else 'ABSENTE (outils clixz inactifs)'}",
        flush=True,
    )
    print(f"[coxyz-mcp] écoute http://{HOST}:{PORT}{MCP_PATH} (config={CONFIG_PATH})", flush=True)
    uvicorn.run(build_app(), host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
