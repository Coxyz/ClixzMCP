# mcp-coxyz — serveur MCP de l'infra Boxyz

Serveur [Model Context Protocol](https://modelcontextprotocol.io) qui donne à
des assistants IA le contexte de l'infrastructure Docker gérée par `clixz` 2.x
(`root_dir` `/srv/docker`) : **inventaire** des services et leur configuration
non sensible, **audit** des permissions et des compose, **exposition** réelle
par le reverse proxy, **règles** en vigueur, **dépôts** de `/opt/repos`, et
**documentation** des conventions.

Aucun secret (`.env`) n'est accessible. Rien n'est jamais écrit dans
l'inventaire : toute mutation est rendue sous forme de **plan**, que l'humain
exécute au clavier. Les seules écritures possibles portent sur `/srv/docs`.

## Ce que voit l'IA

Les outils sont groupés par préfixe. MCP n'a pas de notion de dossier —
`tools/list` est une liste plate — donc le préfixe est le seul regroupement qui
existe.

### `service_*` — inventaire, audit, plans

| Outil | Rôle |
|-------|------|
| `service_list` | liste des services (image, ports, kind, public, url, tags, résumé) — filtres `category`, `public_only` |
| `service_read` | détail d'un service : `service.yaml` + `compose.yaml` (image, ports, volumes, réseaux, dépendances, **noms** des variables d'env — valeurs masquées) |
| `service_search` | recherche par mot-clé (nom, description, tags, techno, catégorie) |
| `service_check` | `clixz check` : dérives de permissions (`findings`), constats sur les compose (`lint`, avec l'identifiant `rule`), écarts acceptés (`ignored`). `exit_code` ≠ 0 = dérive de permissions, pas un échec |
| `service_exposed` | `clixz exposed` : ce que le reverse proxy publie, croisé avec les `service.yaml`. Lit une copie rafraîchie par root (`snapshot_at` donne son âge) |
| `service_create` | **plan** de `clixz new <cat>/<svc>`. N'écrit rien |
| `service_fix` | **plan** de `clixz fix [service]`. N'écrit rien |
| `service_delete` | **plan** de `clixz rm <service>` — un archivage, jamais une destruction. N'écrit rien |

### `categorie_*`, `repo_*`, `boxyz_*`

| Outil | Rôle |
|-------|------|
| `categorie_list` | catégories déclarées, compte propriétaire, services |
| `categorie_read` | une catégorie : compte système, modes applicables, services |
| `categorie_create` | **plan** de `clixz category add <nom>` (compte système, dossier, entrée de config) |
| `repo_list` | dépôts git de `/opt/repos` : branche, remote (identifiants retirés) |
| `repo_create` | **plan** de `clixz repo add <nom> [--url …]` |
| `repo_delete` | **plan** de `clixz repo rm <nom>` — une vraie suppression, pas un archivage |
| `boxyz_config` | `/etc/clixz/config.yaml` en JSON : catégories → comptes `svc_*`, modes par type de chemin |
| `boxyz_rules` | `clixz rules` : niveau de chaque règle de compose (`lint.yaml`), chemins hôte interdits, écarts acceptés avec leur raison (`ignore.yaml`) |

### `document_*` — documentation `/srv/docs`

Les règles et conventions générales (compose, réseau, permissions, durcissement),
que l'IA doit consulter avant de proposer une configuration.

| Outil | Rôle |
|-------|------|
| `document_list` | index : `doc`, titre, **plan des titres de niveau 2**, taille, date — sans charger le contenu |
| `document_read` | contenu Markdown intégral. Accepte `catégorie/nom.md` ou un nom simple s'il est unique |
| `document_create` | crée un nouveau `.md`. Refuse d'écraser un document existant |
| `document_update` | met à jour un document existant. `mode` = `replace` (défaut) ou `append` |
| `document_delete` | retire un document de l'index — en l'archivant sous `.archived/`, jamais en le détruisant |

Les catégories `conventions` et `hardening` sont en lecture seule : ce sont les
règles qui contraignent l'assistant, il ne peut pas les réécrire.

### Le modèle des mutations

Le `compose.yaml` est **écrit à la main** et fait autorité (depuis clixz 2.0 il
n'est plus généré). L'assistant peut en proposer un ; c'est l'utilisateur qui le
place, puis `service_check` le relit.

Chaque outil de mutation renvoie les commandes que clixz exécuterait et
`command_for_the_operator`, la ligne à taper. **Il n'existe pas d'`apply`
distant** : le serveur est joignable par le réseau, l'exécution ne doit pas
l'être.

Ressources : `coxyz://categories`, `coxyz://services`, `coxyz://service/{name}`,
`coxyz://config`, `coxyz://docs`, `coxyz://doc/{name}`.

## Sécurité

- Conteneur **non-root** (`nobody`) + `group_add` des GID `svc_*` → lit les
  `service.yaml` et `compose.yaml` (640) en lecture de groupe, mais **pas** les
  `.env` (600 root) : le système de fichiers refuse l'accès aux secrets.
- Montages en **`:ro`** (sauf `/srv/docs`), rootfs **`read_only`**,
  `cap_drop: ALL`, `no-new-privileges`.
- **`/srv/docs` est la seule exception au `:ro`.** La lecture seule n'y est donc
  plus garantie par le FS : elle repose sur la validation applicative de
  `docs_store.py` — segments de chemin validés par regex, chemin final vérifié
  **après** résolution des liens symboliques, extension `.md` imposée, écriture
  atomique, taille plafonnée. Le GID `opxyz` (1004) donne l'écriture dans les
  sous-dossiers ; `/srv/docs` lui-même reste `root:root 755`, donc le serveur ne
  peut pas créer de catégorie à la racine.
  Les sous-dossiers portent le bit **SGID** (`chmod g+s`) pour que les fichiers
  créés par le conteneur appartiennent au groupe `opxyz` et restent éditables à
  la main — sans lui, ils seraient en `nogroup`.
- Accès protégé par **OAuth** (mode nominal, voir plus bas) : `/mcp` répond `401`
  avec un `WWW-Authenticate` porteur de `resource_metadata`, ce qui déclenche le
  flux OAuth côté client. `/healthz` reste public (healthcheck).
- À défaut d'`OAUTH_ISSUER`, repli sur un **chemin secret** : l'endpoint est servi
  sur `/<MCP_AUTH_TOKEN>/mcp` (URL indevinable), sans `401`. Utile en local ; un
  `401` nu, sans métadonnées OAuth, ferait échouer les connecteurs Claude.
- Données **non sensibles** : même exposées, ce ne sont que des noms de services,
  images, ports internes et chemins de volumes — jamais de secrets.

## Passerelle clixz (`clixz-mcpd`)

Le conteneur ne peut pas exécuter `clixz` : il n'a ni le binaire, ni les
capacités, ni un montage inscriptible de `/srv/docker`. C'est délibéré. Il passe
par **un** démon de l'hôte, joint par socket Unix.

**`clixz-mcpd`** tourne sous le compte `svc_mcprun` (ni `sudo`, ni `docker`),
avec `ReadOnlyPaths=/srv/docker /etc/clixz`. Il exécute les lectures depuis une
liste blanche fermée, arguments validés par regex, `subprocess` sans
`shell=True`. Les mutations, il les transmet à la CLI avec `--plan` : elle
imprime ce qu'elle ferait et n'écrit rien.

Il n'y a plus de démon privilégié derrière lui (`clixz-admind` a été retiré en
2.0). Une évasion dans la passerelle donne la lecture de l'arborescence et le
droit de *demander un plan* — pas d'écriture.

`clixz mcp`, sur l'hôte, liste exactement ce que le démon accepte et les
catégories qu'il peut lire.

> La liste blanche est aussi appliquée côté client (`app/clixz_runner.py`), mais
> ce n'est qu'une commodité : **la barrière est le démon**, seul à exécuter quoi
> que ce soit. Se le rappeler avant d'y toucher.

### `exposed` sans privilège

La base du reverse proxy n'est lisible que par root. Un timer de l'hôte
(`clixz-snapshot.timer`) lance `clixz exposed --snapshot` toutes les 15 minutes ;
root écrit `/etc/clixz/npm-hosts.json`, et c'est cette copie que le démon lit.

### Installation

Les unités vivent dans le dépôt du CLI (`/opt/repos/clixz/deploy/`) et le démon
est installé par pipx sous un chemin `root:root` — un `ExecStart` ne doit jamais
pointer vers un arbre inscriptible par un groupe applicatif.

```bash
sudo install -m 644 /opt/repos/clixz/deploy/clixz-mcpd.service \
                    /opt/repos/clixz/deploy/clixz-snapshot.service \
                    /opt/repos/clixz/deploy/clixz-snapshot.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now clixz-mcpd clixz-snapshot.timer
```

La socket apparaît en `/run/clixz-mcpd/clixz-mcpd.sock` (0660
`svc_mcprun:svc_mcprun`) : le conteneur MCP porte ce GID et peut s'y connecter,
sans pouvoir rien créer dans le dossier. Le montage est en `rw` dans le compose
car se connecter à une socket Unix exige le droit d'écriture sur son inode.

⚠️ `RuntimeDirectoryPreserve=yes` n'est pas cosmétique : sans lui, systemd
recrée le dossier à chaque redémarrage et le montage du conteneur pointe sur un
inode supprimé — la socket disparaît de l'intérieur du conteneur, silencieusement
et définitivement, jusqu'à recréation de celui-ci.

Après une mise à jour de clixz, `sudo systemctl restart clixz-mcpd` : le démon
garde l'ancien code en mémoire.

Si le démon n'est pas installé, le serveur démarre normalement et les outils qui
passent par lui renvoient une erreur explicite (voir la ligne `passerelle clixz`
dans `docker logs mcp`).

### Nouvelle catégorie

Pour que le MCP lise une catégorie créée par `clixz category add`, son groupe
doit être ajouté à `SupplementaryGroups` dans l'unité `clixz-mcpd` **et** à
`group_add` dans `/srv/docker/apps/mcp/compose.yaml`.

## Build de l'image

Contexte : `/opt/images/mcp-coxyz`.

```bash
docker build -t ekyoz/mcp-coxyz:latest /opt/images/mcp-coxyz
```

(ou via Komodo, comme les autres images auto-construites). Le tag est celui que
référence `/srv/docker/apps/mcp/compose.yaml`.

⚠️ Boxyz est un Pi de 4 Go partagé avec la production : ne rien lancer d'autre
de lourd pendant un build.

## Déploiement

Le service vit dans `/srv/docker/apps/mcp` (`compose.yaml`, `service.yaml`, `.env`).
Définir le token dans le `.env` (mode non-OAuth uniquement) :

```
MCP_AUTH_TOKEN=<un-token-long-et-aléatoire>
```

Génération : `openssl rand -hex 32`.

Puis : `cd /srv/docker/apps/mcp && docker compose up -d` (ou via Komodo).

## Reverse proxy (npm)

Ajouter un *Proxy Host* dans Nginx Proxy Manager :

- Domaine : `mcp.coxyz.fr`
- Forward : `mcp` (nom du conteneur) port `8000`, sur le réseau `boxyz_network`
- SSL : certificat Let's Encrypt, *Force SSL*

## Authentification OAuth (Auth0)

Le serveur agit en **Resource Server** : il publie
`/.well-known/oauth-protected-resource/mcp` pointant vers ton tenant Auth0, et
**valide les JWT** (RS256, via le JWKS Auth0 ; vérifie `iss`, `aud`, `exp`).
C'est Auth0 qui gère login + consentement.

### 1. Configurer Auth0

1. Crée un tenant Auth0. Ton **issuer** = `https://<tenant>.<region>.auth0.com/`
   (avec le `/` final ; visible dans n'importe quelle app → Domain).
2. **Applications → APIs → Create API**
   - Name : `Coxyz MCP`
   - **Identifier** (= audience) : `https://mcp.coxyz.fr/mcp`
   - Signing Algorithm : **RS256**
3. **Tenant Settings → General → API Authorization Settings**
   - **Default Audience** : `https://mcp.coxyz.fr/mcp`
     (garantit que les jetons portent le bon `aud` même sans paramètre explicite)
4. Permettre à Claude de s'enregistrer — **une** des deux options :
   - **A. Enregistrement dynamique (DCR)** — *Tenant Settings → Advanced* →
     active **OIDC Dynamic Application Registration** ; définis un **Default
     Directory** (nom d'une connexion Database). Claude s'enregistre alors tout
     seul. ⚠️ Deux réglages supplémentaires sont **indispensables**, voir
     « DCR : les deux pièges » ci-dessous.
   - **B. Client manuel** — *Applications → Create Application → Regular Web App*.
     Dans **Allowed Callback URLs**, ajoute l'URL de redirection de Claude
     (ex. `https://claude.ai/api/mcp/auth_callback` ; web te la donne à l'écran).
     Copie le **Client ID** et colle-le dans Claude (« add an OAuth Client ID »).

#### DCR : les deux pièges

La DCR crée des clients **third-party** (`client_id` préfixé `tpc_`), et Auth0
leur applique deux restrictions qui, non levées, font échouer `/authorize` avec
une page « Oops!, something went wrong » et un `HTTP 400` — sans message
exploitable côté navigateur. La cause réelle n'apparaît que dans
*Monitoring → Logs*.

**1. Autoriser les clients third-party sur l'API.** Sans ça, le log dit
`Client "tpc_..." is not authorized to access resource server`. Un client grant
« par défaut » couvre d'un coup tous les clients DCR, présents et futurs (pas
d'équivalent dans le dashboard, c'est du Management API uniquement) :

```bash
curl -X POST "https://<tenant>.<region>.auth0.com/api/v2/client-grants" \
  -H "Authorization: Bearer $MGMT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"default_for":"third_party_clients","audience":"https://mcp.coxyz.fr/mcp",
       "scope":["read:services"],"subject_type":"user"}'
```

**2. Promouvoir la connexion au niveau domaine.** Un client third-party ne voit
que les connexions marquées `is_domain_connection` — sinon aucune méthode de
login ne lui est proposée :

```bash
curl -X PATCH "https://<tenant>.<region>.auth0.com/api/v2/connections/<con_id>" \
  -H "Authorization: Bearer $MGMT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"is_domain_connection":true}'
```

L'API doit par ailleurs avoir `allow_offline_access: true` (Claude demande le
scope `offline_access` pour rafraîchir ses jetons) et au moins un scope déclaré.

> 🔒 Avec la DCR activée, **ferme les inscriptions** sur la connexion Database
> (`{"options":{"disable_signup":true}}`), sinon n'importe qui découvrant
> l'URL peut se créer un compte et lire ton inventaire d'infra. Crée ton
> utilisateur via *User Management → Users → Create User*.

Vérification sans navigateur — un `302` vers `/u/login` signifie que tout est
bon, un `400` qu'il reste un des deux pièges :

```bash
curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' \
  "https://<tenant>.<region>.auth0.com/authorize?response_type=code&client_id=<tpc_...>&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&code_challenge=x&code_challenge_method=S256&state=t&scope=openid+offline_access&resource=https%3A%2F%2Fmcp.coxyz.fr%2Fmcp"
```

### 2. Renseigner le `.env` du service

```
OAUTH_ISSUER=https://<tenant>.<region>.auth0.com/
OAUTH_AUDIENCE=https://mcp.coxyz.fr/mcp
OAUTH_RESOURCE_URL=https://mcp.coxyz.fr/mcp
# OAUTH_REQUIRED_SCOPES=        # optionnel
# OAUTH_DEBUG=1                 # logge les rejets de jeton (diagnostic)
```

> ⚠️ `OAUTH_ISSUER` est la **racine** du tenant, avec le `/` final et **rien
> d'autre** — pas de `/api/v2/` (ça, c'est l'audience de la Management API, un
> tout autre usage). Avec un suffixe, le JWKS et les métadonnées du serveur
> d'autorisation renvoient 404, et le `iss` des jetons ne correspond plus : le
> flux OAuth échoue en silence côté client. Valeur de référence = le champ
> `issuer` de :
>
> ```bash
> curl -s https://<tenant>.<region>.auth0.com/.well-known/openid-configuration | jq .issuer
> ```

Puis redéploie : `cd /srv/docker/apps/mcp && docker compose up -d`.

> Si `OAUTH_ISSUER` est absent, le serveur retombe en mode **chemin secret**
> (`/<MCP_AUTH_TOKEN>/mcp`, sans OAuth) — pratique pour tester en local.

### 3. Connecter une IA

**Endpoint** : `https://mcp.coxyz.fr/mcp`

- **Claude web** : Réglages → Connecteurs → Ajouter → URL `https://mcp.coxyz.fr/mcp`.
  Claude détecte l'OAuth, t'ouvre la page Auth0, tu te connectes → c'est lié.
  (Avec l'option B, colle d'abord le Client ID dans les réglages du connecteur.)
- **Claude Code** :
  ```bash
  claude mcp add --transport http clixz https://mcp.coxyz.fr/mcp
  ```
  Au premier appel, Claude Code lance le flux OAuth dans le navigateur.

### Dépannage

- 401 en boucle / jeton rejeté → mets `OAUTH_DEBUG=1`, regarde
  `docker logs mcp` : la cause exacte est loggée (`aud`, `iss`, `exp`…).
  Le plus fréquent : `aud` du jeton ≠ `OAUTH_AUDIENCE` → vérifie le **Default
  Audience** Auth0 et l'Identifier de l'API.
- Vérifie la découverte Auth0 :
  `curl https://<tenant>.<region>.auth0.com/.well-known/openid-configuration`

## Test rapide (local, sans proxy)

```bash
docker run --rm -p 18000:8000 \
  --user 65534 --group-add 981 --group-add 982 --group-add 983 \
  --group-add 985 --group-add 987 --group-add 1004 \
  -e MCP_AUTH_TOKEN=test -e CLIXZ_DOCS_RW=1 \
  -v /srv/docker:/srv/docker:ro \
  -v /etc/clixz/config.yaml:/etc/clixz/config.yaml:ro \
  -v /srv/docs:/srv/docs:rw \
  --group-add 979 \
  -v /run/clixz-mcpd:/run/clixz-mcpd \
  ekyoz/mcp-coxyz:latest
# health : curl http://127.0.0.1:18000/healthz   → ok
```

Les trois lignes de log au démarrage disent l'état réel : mode d'authentification,
`docs … LECTURE/ÉCRITURE` ou `lecture seule`, et `passerelle clixz … disponible`
ou `ABSENTE`.

## Variables d'environnement

| Variable | Défaut | Rôle |
|----------|--------|------|
| `MCP_AUTH_TOKEN` | *(vide)* | secret de **chemin** : endpoint servi sur `/<token>/mcp` ; si vide, sur `/mcp` (ouvert) |
| `MCP_HOST` | `0.0.0.0` | interface d'écoute |
| `MCP_PORT` | `8000` | port d'écoute |
| `CLIXZ_CONFIG` | `/etc/clixz/config.yaml` | chemin du config clixz |
| `CLIXZ_ROOT` | *(config)* | override du `root_dir` |
| `CLIXZ_DOCS` | `/srv/docs` | racine des documents de référence |
| `CLIXZ_DOCS_RW` | *(non)* | `1` pour activer `document_create` / `update` / `delete` |
| `CLIXZ_MCPD_SOCKET` | `/run/clixz-mcpd/clixz-mcpd.sock` | socket de la passerelle `clixz-mcpd` |
| `CLIXZ_MCPD_TIMEOUT` | `70` | délai d'attente client, en secondes |

## Dépendances

`mcp` est borné à **`<2`** : la version 2.0 déplace `FastMCP` et
`mcp.server.fastmcp` disparaît, ce qui casse l'import. Ne pas relever la borne
sans adapter `server.py`.
