"""Validation des jetons OAuth (mode Resource Server) pour un IdP externe (Auth0).

Le serveur MCP ne fait PAS office de serveur d'autorisation : c'est l'IdP
(Auth0) qui gère login/consentement et émet des JWT. Ici on se contente de
**vérifier** ces JWT (signature RS256 via le JWKS de l'IdP, issuer, audience,
expiration) et d'en extraire un ``AccessToken`` pour la lib MCP.

Configuration (variables d'environnement) :
  OAUTH_ISSUER          ex. https://ton-tenant.eu.auth0.com/   (avec slash final)
  OAUTH_AUDIENCE        identifiant de l'API Auth0 = ``aud`` attendu
                        (ex. https://mcp.coxyz.fr/mcp)
  OAUTH_RESOURCE_URL    URL publique du serveur MCP (pour les métadonnées ;
                        def. = OAUTH_AUDIENCE)
  OAUTH_REQUIRED_SCOPES scopes requis, séparés par des espaces (optionnel)
  OAUTH_JWKS_URL        override du JWKS (def. <issuer>/.well-known/jwks.json)
  OAUTH_ALGORITHMS      def. RS256
"""

from __future__ import annotations

import logging
import os

import anyio
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier

logger = logging.getLogger("coxyz-mcp.auth")
_DEBUG = os.environ.get("OAUTH_DEBUG", "").strip() not in ("", "0", "false", "False")


def oauth_config() -> dict | None:
    """Retourne la config OAuth si OAUTH_ISSUER est défini, sinon None."""
    issuer = os.environ.get("OAUTH_ISSUER", "").strip()
    if not issuer:
        return None
    audience = os.environ.get("OAUTH_AUDIENCE", "").strip()
    if not audience:
        raise RuntimeError("OAUTH_ISSUER défini mais OAUTH_AUDIENCE manquant")
    resource = os.environ.get("OAUTH_RESOURCE_URL", "").strip() or audience
    scopes = os.environ.get("OAUTH_REQUIRED_SCOPES", "").split()
    jwks_url = os.environ.get("OAUTH_JWKS_URL", "").strip() or (
        issuer.rstrip("/") + "/.well-known/jwks.json"
    )
    algorithms = (os.environ.get("OAUTH_ALGORITHMS", "RS256").split() or ["RS256"])
    return {
        "issuer": issuer,
        "audience": audience,
        "resource": resource,
        "required_scopes": scopes,
        "jwks_url": jwks_url,
        "algorithms": algorithms,
    }


class JWTVerifier(TokenVerifier):
    """Vérifie un JWT émis par l'IdP via son JWKS (clés mises en cache)."""

    def __init__(self, *, issuer: str, audience: str, jwks_url: str,
                 algorithms: list[str], required_scopes: list[str] | None = None):
        self.issuer = issuer
        self.audience = audience
        self.required_scopes = set(required_scopes or [])
        self.algorithms = algorithms
        # PyJWKClient gère le téléchargement + cache des clés de signature.
        self._jwks = jwt.PyJWKClient(jwks_url)

    def _verify_sync(self, token: str) -> AccessToken | None:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat"]},
            )
        except Exception as exc:
            if _DEBUG:
                # Aide au diagnostic (ex. audience/issuer/expiration). Ne logge
                # jamais le jeton complet.
                logger.warning("rejet du JWT : %s: %s", type(exc).__name__, exc)
            return None

        raw_scope = claims.get("scope")
        if isinstance(raw_scope, str):
            scopes = raw_scope.split()
        elif isinstance(claims.get("scopes"), list):
            scopes = [str(s) for s in claims["scopes"]]
        else:
            scopes = []
        if self.required_scopes and not self.required_scopes.issubset(scopes):
            return None

        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("client_id") or claims.get("sub") or ""),
            scopes=scopes,
            expires_at=claims.get("exp"),
            subject=str(claims.get("sub")) if claims.get("sub") else None,
            resource=self.audience,
            claims=claims,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        # La validation (et l'éventuel fetch JWKS) est synchrone et peut faire du
        # réseau : on l'exécute dans un thread pour ne pas bloquer la boucle async.
        return await anyio.to_thread.run_sync(self._verify_sync, token)
