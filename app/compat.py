"""Compatibilité avec l'ancien nom de la CLI (``coxyz``, devenue ``clixz``).

Le renommage est cosmétique, mais l'environnement de ce serveur ne l'est pas :
ses variables vivent dans la configuration Komodo de la stack, que ce dépôt ne
peut pas modifier. Lire les deux orthographes évite de casser le déploiement en
cours au premier redémarrage.

Les anciens noms sont lus, jamais écrits.
"""

from __future__ import annotations

import os


def env(suffix: str, default: str = "") -> str:
    """Lit ``CLIXZ_<suffix>``, à défaut ``COXYZ_<suffix>``, à défaut ``default``.

    Une valeur vide compte comme absente : Komodo écrit volontiers une variable
    vide pour une option laissée en blanc, et cela ne doit pas masquer une
    valeur encore définie sous l'ancien nom.
    """
    value = os.environ.get(f"CLIXZ_{suffix}", "").strip()
    if value:
        return value
    return os.environ.get(f"COXYZ_{suffix}", "").strip() or default


def first_existing(*paths: str) -> str:
    """Le premier chemin qui existe, sinon le premier de la liste.

    Sert aux sockets et aux fichiers de config, dont l'emplacement change avec
    le renommage : on préfère le nouveau, on accepte l'ancien tant que l'hôte
    n'a pas été migré.
    """
    for path in paths:
        if path and os.path.exists(path):
            return path
    return paths[0]
