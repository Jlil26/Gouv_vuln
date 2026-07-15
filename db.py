# -*- coding: utf-8 -*-
"""
=====================================================================
 Module `db.py` — Gestion des comptes citoyens (Togo-Services)
=====================================================================

Ce module gère la création de compte et l'authentification des
usagers. Il est ENTIÈREMENT hors du périmètre des deux vulnérabilités
pédagogiques du projet (A05 et A06) : il applique donc, quel que soit
l'état de SECURE_MODE, les bonnes pratiques standard :

  - Requêtes SQL PARAMÉTRÉES (placeholders "?") -> aucune injection SQL
    possible, y compris en mode "vulnérable" de la démonstration.
  - Mots de passe JAMAIS stockés en clair : hachage salé via
    werkzeug.security.generate_password_hash (PBKDF2/Scrypt selon la
    version de Werkzeug installée).
  - Contrainte d'unicité sur l'e-mail au niveau de la base de données.

⚠️ Rappel : SEULES les vulnérabilités décrites dans app.py (en-têtes
HTTP / accès à /admin/system-status / SSTI sur /assistance) doivent
rester exploitables en mode SECURE_MODE=False. Ce module n'introduit
et ne doit introduire AUCUNE vulnérabilité supplémentaire.
=====================================================================
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.security import generate_password_hash, check_password_hash

CHEMIN_BASE = Path(__file__).parent / "togo_services.db"


def obtenir_connexion():
    """Ouvre une connexion SQLite avec les lignes accessibles par nom de colonne."""
    connexion = sqlite3.connect(CHEMIN_BASE)
    connexion.row_factory = sqlite3.Row
    # Applique les contraintes de clé étrangère (bonne pratique, même si
    # non utilisées ici pour l'instant).
    connexion.execute("PRAGMA foreign_keys = ON")
    return connexion


def initialiser_base():
    """Crée la table des usagers si elle n'existe pas encore."""
    with obtenir_connexion() as connexion:
        connexion.execute(
            """
            CREATE TABLE IF NOT EXISTS usagers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                numero_usager TEXT UNIQUE NOT NULL,
                prenom TEXT NOT NULL,
                nom TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                telephone TEXT,
                ville TEXT,
                mot_de_passe_hash TEXT NOT NULL,
                date_creation TEXT NOT NULL
            )
            """
        )
        connexion.commit()


def _generer_numero_usager(connexion) -> str:
    """Génère un numéro d'usager séquentiel au format TG-2026-000123."""
    annee = datetime.now(timezone.utc).year
    curseur = connexion.execute("SELECT COUNT(*) AS total FROM usagers")
    total = curseur.fetchone()["total"] + 1
    return f"TG-{annee}-{total:06d}"


def email_deja_utilise(email: str) -> bool:
    with obtenir_connexion() as connexion:
        ligne = connexion.execute(
            "SELECT 1 FROM usagers WHERE email = ?", (email.strip().lower(),)
        ).fetchone()
        return ligne is not None


def creer_usager(prenom: str, nom: str, email: str, telephone: str, ville: str, mot_de_passe: str):
    """
    Crée un nouvel usager. Le mot de passe est haché avant stockage
    (jamais conservé en clair). Retourne le dictionnaire de l'usager créé.
    """
    email_normalise = email.strip().lower()
    hash_mdp = generate_password_hash(mot_de_passe)
    date_creation = datetime.now(timezone.utc).isoformat()

    with obtenir_connexion() as connexion:
        numero_usager = _generer_numero_usager(connexion)
        # Requête paramétrée : les valeurs utilisateur ne sont JAMAIS
        # concaténées dans la chaîne SQL -> immunisé contre l'injection SQL.
        connexion.execute(
            """
            INSERT INTO usagers (numero_usager, prenom, nom, email, telephone, ville, mot_de_passe_hash, date_creation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (numero_usager, prenom.strip(), nom.strip(), email_normalise, telephone.strip(), ville.strip(), hash_mdp, date_creation),
        )
        connexion.commit()

    return {
        "numero_usager": numero_usager,
        "prenom": prenom.strip(),
        "nom": nom.strip(),
        "email": email_normalise,
    }


def verifier_identifiants(email: str, mot_de_passe: str):
    """
    Vérifie les identifiants de connexion. Retourne l'usager (dict) si
    valides, sinon None. Utilise check_password_hash (comparaison
    constante, résistante aux attaques temporelles) plutôt qu'une
    comparaison directe de chaînes.
    """
    with obtenir_connexion() as connexion:
        ligne = connexion.execute(
            "SELECT * FROM usagers WHERE email = ?", (email.strip().lower(),)
        ).fetchone()

    if ligne is None:
        return None
    if not check_password_hash(ligne["mot_de_passe_hash"], mot_de_passe):
        return None

    return dict(ligne)


def obtenir_usager_par_id(usager_id: int):
    with obtenir_connexion() as connexion:
        ligne = connexion.execute(
            "SELECT * FROM usagers WHERE id = ?", (usager_id,)
        ).fetchone()
    return dict(ligne) if ligne else None
