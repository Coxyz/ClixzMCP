# ClixzMCP — serveur MCP de l'infra Boxyz

Serveur [Model Context Protocol](https://modelcontextprotocol.io) qui donne à
des assistants IA l'infrastructure Docker gérée par
[`clixz`](https://github.com/Coxyz/Clixz) 2.3+ (`root_dir` `/srv/docker`) :
**inventaire** des services et leur configuration non sensible, **audit** des
permissions et des compose, **exposition** réelle par le reverse proxy,
**règles** en vigueur, **plans** de création et de modification de service que
l'IA applique après accord, **todo** de l'opérateur, **dépôts** de
`/opt/repos` et **documentation** des conventions.

Aucun secret (`.env`) n'est accessible. Le conteneur n'écrit rien dans
`/srv/docker`, qu'il monte en lecture seule : les changements passent par la
passerelle de l'hôte, qui les relaie à un processus root démarré pour une seule
requête et qui revalide tout (voir plus bas).

## Ce que voit l'IA

Les outils sont groupés par préfixe — MCP n'a pas de notion de dossier.

### `todo_*` — ce qui reste à faire

| Outil | Rôle |
|-------|------|
| `todo_list` | éléments ouverts (`todo`, `doing`) ; `state`, `include_closed` |
| `todo_read` | un élément et sa description |
| `todo_create` / `todo_update` / `todo_delete` | mêmes droits que l'opérateur avec `clixz todo` |

### `service_*` et `plan_*` — inventaire, audit, changements

| Outil | Rôle |
|-------|------|
| `service_list` / `service_read` / `service_search` | inventaire : `service.yaml` + `compose.yaml` (**noms** des variables d'env seulement) |
| `service_check` | `clixz check` : dérives de permissions, lint des compose, écarts acceptés |
| `service_exposed` | ce que le reverse proxy publie, **lu au moment de l'appel**, croisé avec les `service.yaml` |
| `service_create` | **plan** d'un nouveau service : son compose et son service.yaml (ou les gabarits) |
| `service_update` | **plan** de remplacement du compose et/ou du service.yaml, avec le diff |
| `service_fix` / `service_delete` | **plans** de correction des permissions, d'archivage |
| `plan_list` / `plan_read` / `plan_delete` | les plans enregistrés |
| `plan_apply` | **applique** un plan — annoté `destructiveHint` |

### `categorie_*`, `repo_*`, `boxyz_*`, `document_*`

| Outil | Rôle |
|-------|------|
| `categorie_list` / `categorie_read` | catégories, compte propriétaire, services |
| `categorie_create` | **plan à taper** par l'opérateur (`clixz category add`) |
| `repo_list` / `repo_create` / `repo_delete` | dépôts git ; création et suppression = plans à taper |
| `boxyz_config` / `boxyz_rules` | `/etc/clixz/config.yaml` ; `lint.yaml` et `ignore.yaml` |
| `document_list` / `document_read` / `document_create` / `document_update` / `document_delete` | `/srv/docs` ; `conventions` et `hardening` en lecture seule |

### Ressources

| Ressource | Contenu |
|-----------|---------|
| `clixz://overview` | synthèse Markdown à jour : todo, plans en attente, services, exposition, audit — **celle à joindre à un projet Claude** |
| `clixz://todo` | la todo ouverte |
| `clixz://plans`, `clixz://rules`, `clixz://exposed`, `clixz://check` | plans, règles, exposition, audit (JSON) |
| `clixz://categories`, `clixz://services`, `clixz://service/{name}`, `clixz://config`, `clixz://docs`, `clixz://doc/{name}` | inventaire et documentation |

Le schéma s'appelait `coxyz://` jusqu'à clixz 2.2 : une ressource jointe à un
projet sous l'ancien nom est à rattacher.

## Le modèle des changements

1. L'IA demande un plan (`service_create`, `service_update`, `service_fix`,
   `service_delete`). clixz le **calcule** — commandes, diff, lint — sans rien
   écrire, et le **refuse** si le compose porte une erreur de lint que
   `ignore.yaml` n'accepte pas (`privileged`, `docker.sock`, `/` monté,
   `network_mode: host`…). L'IA ne peut modifier ni `lint.yaml` ni `ignore.yaml`.
2. Root **enregistre** le plan sous un id aléatoire (`/var/lib/clixz/plans/`,
   0700) : seul root écrit là, donc un id prouve que clixz a calculé le plan.
3. L'IA montre le plan à l'utilisateur et n'appelle `plan_apply` qu'après son
   accord. **Laisse `plan_apply` sur « demander à chaque fois »** dans les
   réglages du connecteur : c'est la validation humaine. Les outils de lecture
   peuvent être autorisés en permanence.
4. clixz **recalcule** le plan contre le disque, le refuse si le service a
   changé entre-temps, l'applique une fois, régénère le manifest et, pour un
   nouveau service, **crée sa stack dans Komodo** — sans la déployer.

Le `.env` n'est jamais écrit (Komodo le remplit) et rien n'est jamais déployé
par clixz : l'opérateur renseigne l'environnement et déploie dans Komodo.

## Sécurité

- Conteneur **non-root** (`nobody`) + `group_add` des GID `svc_*` → lit les
  `service.yaml` et `compose.yaml` (640) en lecture de groupe, mais **pas** les
  `.env` : aucun de ces groupes ne les possède.
- Montages en **`:ro`** (sauf `/srv/docs`), rootfs **`read_only`**,
  `cap_drop: ALL`, `no-new-privileges`.
- **`/srv/docs` est la seule exception au `:ro`.** La lecture seule y repose sur
  `docs_store.py` — segments de chemin validés par regex, chemin final vérifié
  **après** résolution des liens symboliques, extension `.md` imposée, écriture
  atomique, taille plafonnée. Le GID `opxyz` (1004) donne l'écriture dans les
  sous-dossiers ; `/srv/docs` lui-même reste `root:root 755`. Les sous-dossiers
  portent le bit **SGID** pour que les fichiers créés restent au groupe `opxyz`.
- Accès protégé par **OAuth** (Auth0, voir plus bas). `/healthz` reste public.
- Le chemin Internet → Auth0 → écriture root dans `/srv/docker` **existe**
  depuis clixz 2.3. Il est borné par l'approbation de `plan_apply` dans le
  client, le refus des erreurs de lint non acceptées, le recalcul avant
  application, et ce que le bac à sable de `clixz-apply` permet d'écrire
  (l'arbre des services, son état, le manifest — pas la config ni les règles).

## Passerelle clixz (hôte)

Le conteneur parle à **`clixz-mcpd`** par la socket
`/run/clixz-mcpd/clixz-mcpd.sock` (0660 `svc_mcprun`, GID 979 dans `group_add`).
Ce démon tourne sans privilège et n'écrit rien : il exécute les lectures par la
CLI, et relaie plans, applications, `exposed` et écritures de la todo à
**`clixz-apply`** — un processus root démarré par systemd pour une requête
(`clixz-apply.socket`), sur une socket que le conteneur ne voit pas.

Les deux s'installent depuis le paquet clixz :

```bash
sudo clixz daemon install    # unités, compte svc_mcprun, /var/lib/clixz
clixz daemon status          # unités à jour ? démarrées ?
clixz mcp                    # ce que la passerelle exécute, relaie, et ne fait jamais
```

`clixz upgrade` met à jour les unités et relance la passerelle ; elle se relance
aussi d'elle-même après toute mise à jour.

⚠️ `RuntimeDirectoryPreserve=yes` dans l'unité n'est pas cosmétique : sans lui,
systemd recrée `/run/clixz-mcpd` à chaque redémarrage et le montage du conteneur
pointe sur un inode supprimé — la socket disparaît de l'intérieur du conteneur
jusqu'à sa recréation.

### Nouvelle catégorie

Après `clixz category add`, `sudo clixz daemon install` donne la catégorie à
lire à la passerelle ; ajoute aussi le **GID du groupe** à `group_add` dans
`/srv/docker/ia/mcp/compose.yaml` (`service_update` le fait par un plan) et
redéploie.

## Build de l'image

Contexte : `/opt/images/mcp-clixz` (ce dépôt).

```bash
docker build -t ekyoz/mcp-clixz:latest /opt/images/mcp-clixz
```

Le tag est celui que référence `/srv/docker/ia/mcp/compose.yaml`.

⚠️ Boxyz est un Pi de 4 Go partagé avec la production : vérifier la mémoire
libre (`free -h`) avant un build, et ne rien lancer d'autre de lourd pendant.

## Déploiement

Le service vit dans `/srv/docker/ia/mcp` (`compose.yaml`, `service.yaml`,
`.env`), déployé par Komodo (stack `mcp-clixz`). Après un build : redéployer la
stack dans Komodo.

## Reverse proxy (npm)

Ajouter un *Proxy Host* dans Nginx Proxy Manager :

- Domaine : `clixz.coxyz.fr`
- Forward : `mcp-clixz` (nom du conteneur) port `8000`, sur le réseau `boxyz_network`
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
   - Name : `Clixz MCP`
   - **Identifier** (= audience) : `https://clixz.coxyz.fr/mcp`
   - Signing Algorithm : **RS256**
3. **Tenant Settings → General → API Authorization Settings**
   - **Default Audience** : `https://clixz.coxyz.fr/mcp`
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
  -d '{"default_for":"third_party_clients","audience":"https://clixz.coxyz.fr/mcp",
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
  "https://<tenant>.<region>.auth0.com/authorize?response_type=code&client_id=<tpc_...>&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&code_challenge=x&code_challenge_method=S256&state=t&scope=openid+offline_access&resource=https%3A%2F%2Fclixz.coxyz.fr%2Fmcp"
```

### 2. Renseigner le `.env` du service

```
OAUTH_ISSUER=https://<tenant>.<region>.auth0.com/
OAUTH_AUDIENCE=https://clixz.coxyz.fr/mcp
OAUTH_RESOURCE_URL=https://clixz.coxyz.fr/mcp
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

Puis redéploie la stack dans Komodo.

> Si `OAUTH_ISSUER` est absent, le serveur retombe en mode **chemin secret**
> (`/<MCP_AUTH_TOKEN>/mcp`, sans OAuth) — pratique pour tester en local.

### 3. Connecter une IA

**Endpoint** : `https://clixz.coxyz.fr/mcp`

- **Claude web** : Réglages → Connecteurs → Ajouter → URL `https://clixz.coxyz.fr/mcp`.
  Claude détecte l'OAuth, t'ouvre la page Auth0, tu te connectes → c'est lié.
  (Avec l'option B, colle d'abord le Client ID dans les réglages du connecteur.)
- **Claude Code** :
  ```bash
  claude mcp add --transport http clixz https://clixz.coxyz.fr/mcp
  ```
  Au premier appel, Claude Code lance le flux OAuth dans le navigateur.

### Dépannage

- 401 en boucle / jeton rejeté → mets `OAUTH_DEBUG=1`, regarde
  `docker logs mcp-clixz` : la cause exacte est loggée (`aud`, `iss`, `exp`…).
  Le plus fréquent : `aud` du jeton ≠ `OAUTH_AUDIENCE` → vérifie le **Default
  Audience** Auth0 et l'Identifier de l'API.
- Vérifie la découverte Auth0 :
  `curl https://<tenant>.<region>.auth0.com/.well-known/openid-configuration`

## Test rapide (hors Boxyz)

⚠️ Pas sur Boxyz : un conteneur de test à côté de la production a déjà saturé
la mémoire du Pi (2026-09-30). Sur une autre machine, ou sans conteneur — un
venv avec `requirements.txt` suffit pour importer `app/server.py` et appeler
les outils, la passerelle simulée :

```bash
python -m venv /tmp/mcpvenv && /tmp/mcpvenv/bin/pip install -r requirements.txt
MCP_AUTH_TOKEN=test /tmp/mcpvenv/bin/python -c "import sys; sys.path.insert(0, 'app'); import server"
```

Au démarrage, trois lignes de log disent l'état réel : mode d'authentification,
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
| `CLIXZ_MCPD_TIMEOUT` | `130` | délai d'attente client, en secondes (un apply peut créer une stack Komodo) |

## Dépendances

`mcp` est borné à **`<2`** : la version 2.0 déplace `FastMCP` et
`mcp.server.fastmcp` disparaît, ce qui casse l'import. Ne pas relever la borne
sans adapter `server.py`.
