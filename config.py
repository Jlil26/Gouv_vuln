# -*- coding: utf-8 -*-
"""
Configuration de l'application « Gouv-Services ».

Ce fichier centralise les réglages de sécurité. La variable SECURE_MODE
est le point de bascule unique utilisé pour la démonstration « Avant / Après » :

    SECURE_MODE = False -> les vulnérabilités pédagogiques sont ACTIVES
    SECURE_MODE = True  -> les correctifs de sécurité sont APPLIQUÉS

Elle peut être surchargée par la variable d'environnement SECURE_MODE
(valeurs acceptées : "true"/"false", "1"/"0"), ce qui permet de basculer
le mode sans toucher au code pendant la présentation.
"""

import os


def _str_to_bool(value: str) -> bool:
    """Convertit une chaîne d'environnement en booléen."""
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class Config:
    # --- Bascule pédagogique principale --------------------------------
    # C'est LA variable à changer (ou à surcharger via l'env) pendant la démo.
    SECURE_MODE: bool = _str_to_bool(os.environ.get("SECURE_MODE", "False"))

    # --- Réglages généraux Flask ----------------------------------------
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-key-a-changer-en-production")

    # En mode vulnérable, on garde DEBUG actif pour simuler une erreur de
    # configuration classique (Werkzeug debugger exposé). En mode sécurisé,
    # DEBUG est impérativement désactivé.
    DEBUG: bool = not SECURE_MODE

    # --- Identifiants de l'espace d'administration ----------------------
    # Utilisés uniquement en mode SECURE_MODE = True pour protéger
    # /admin/system-status par une authentification réelle.
    ADMIN_USERNAME: str = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.environ.get("ADMIN_PASSWORD", "ChangeMoiImmediatement!2024")

    # --- Divers -----------------------------------------------------------
    APP_NAME: str = "Gouv-Services — Portail National des Services Citoyens"
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    # Le cookie "Secure" nécessite HTTPS ; à activer derrière Nginx/TLS en prod.
    SESSION_COOKIE_SECURE: bool = _str_to_bool(os.environ.get("SESSION_COOKIE_SECURE", "False"))
