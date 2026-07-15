# -*- coding: utf-8 -*-
"""
=====================================================================
 Togo-Services — Portail National des Services Publics du Togo
 (démonstrateur pédagogique d'audit de sécurité)
=====================================================================

Application illustrant volontairement DEUX vulnérabilités du Top 10
OWASP 2021, et UNIQUEMENT celles-ci :

  1) A05:2021 - Security Misconfiguration
     - En-têtes HTTP bavards (Server / X-Powered-By détaillés)
     - Endpoint /admin/system-status accessible sans authentification

  2) A06:2021 - Vulnerable and Outdated Components
     - requirements.txt figeant des versions obsolètes
     - Route /assistance vulnérable à une injection de gabarit côté
       serveur (SSTI) via render_template_string() sur une entrée
       utilisateur non filtrée

Le comportement bascule intégralement via config.SECURE_MODE :
  - False -> vulnérabilités actives (mode "AVANT")
  - True  -> correctifs appliqués (mode "APRÈS")

Le système de création de compte / connexion citoyenne (routes
/inscription, /connexion, /deconnexion) est un module ANNEXE qui
applique en permanence, quel que soit SECURE_MODE, les bonnes
pratiques standard (mots de passe hachés, requêtes SQL paramétrées,
session signée). Il ne fait PAS partie du périmètre des vulnérabilités
pédagogiques et ne doit jamais en introduire de nouvelles.

⚠️  Cette application est fournie à des fins de formation/démonstration
    en environnement isolé. Ne JAMAIS déployer le mode SECURE_MODE=False
    sur un réseau exposé. Ce n'est pas le site officiel du Gouvernement
    togolais (gouv.tg / togo.gouv.tg) : démonstrateur technique.
=====================================================================
"""

import platform
import re
import sys
from datetime import datetime
from functools import wraps

import flask
from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    session,
    redirect,
    url_for,
    flash,
)
from markupsafe import escape

from config import Config
import db

app = Flask(__name__)
app.config.from_object(Config)

# Initialise la base SQLite des usagers au démarrage (idempotent).
db.initialiser_base()

# Horodatage de démarrage, affiché sur la page d'état système.
APP_START_TIME = datetime.utcnow()

REGEX_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------
# Données de démonstration — services publics togolais
# ---------------------------------------------------------------------

SERVICES_RAPIDES = [
    {
        "slug": "identite",
        "titre": "Carte d'identité biométrique",
        "description": "Pré-enrôlement ANIP, prise de rendez-vous, suivi de production de la CNI biométrique.",
        "icone": "file-text",
        "delai": "3 à 4 semaines",
        "organisme": "ANIP",
    },
    {
        "slug": "impots",
        "titre": "Impôts & Taxes (OTR)",
        "description": "Déclaration en ligne, paiement des impôts, attestation de régularité fiscale.",
        "icone": "landmark",
        "delai": "Instantané",
        "organisme": "OTR",
    },
    {
        "slug": "passeport",
        "titre": "Passeport togolais",
        "description": "Pré-demande, prise de rendez-vous, suivi de fabrication du passeport biométrique.",
        "icone": "book-user",
        "delai": "4 à 6 semaines",
        "organisme": "Ministère des Affaires Étrangères",
    },
    {
        "slug": "etat-civil",
        "titre": "État civil",
        "description": "Actes de naissance, de mariage et de décès, copies intégrales auprès de la mairie.",
        "icone": "home",
        "delai": "48h en ligne",
        "organisme": "Mairies / OTR",
    },
    {
        "slug": "permis",
        "titre": "Permis de conduire",
        "description": "Demande, renouvellement et duplicata de permis de conduire.",
        "icone": "car-front",
        "delai": "10 jours ouvrés",
        "organisme": "Ministère des Transports",
    },
    {
        "slug": "amu",
        "titre": "Assurance Maladie Universelle",
        "description": "Enrôlement AMU/INAM, mise à jour des ayants droit, suivi des remboursements.",
        "icone": "heart-pulse",
        "delai": "Sous 5 jours",
        "organisme": "INAM",
    },
]

DASHBOARD_DEMARCHES = [
    {"nom": "Renouvellement du passeport", "statut": "En cours", "avancement": 65, "couleur": "vert"},
    {"nom": "Déclaration OTR 2025", "statut": "Validée", "avancement": 100, "couleur": "jaune"},
    {"nom": "Enrôlement carte d'identité (ANIP)", "statut": "En attente de pièces", "avancement": 30, "couleur": "rouge"},
]

DASHBOARD_ALERTES = [
    {"type": "info", "message": "La campagne déclarative OTR 2026 ouvrira le 3 avril à Lomé et dans les régions."},
    {"type": "warning", "message": "Votre pièce d'identité expire dans 90 jours — pensez à l'enrôlement ANIP."},
    {"type": "success", "message": "Votre remboursement AMU de 15 000 FCFA a été traité."},
]


# ---------------------------------------------------------------------
# Sécurité : en-têtes HTTP
# ---------------------------------------------------------------------
@app.after_request
def gerer_entetes_securite(response):
    """
    Applique les en-têtes HTTP selon le mode courant.

    Mode vulnérable (SECURE_MODE=False) :
        -> simule une "Security Misconfiguration" (A05) en exposant
           la pile technique complète (serveur, framework, version).

    Mode sécurisé (SECURE_MODE=True) :
        -> retire les informations techniques et ajoute les en-têtes
           de durcissement recommandés (OWASP Secure Headers Project).
    """
    if not app.config["SECURE_MODE"]:
        # --- MODE VULNÉRABLE ------------------------------------------------
        # Fuite volontaire d'informations sur la pile technique.
        response.headers["Server"] = f"Werkzeug/2.0.1 Python/{platform.python_version()}"
        response.headers["X-Powered-By"] = f"Flask/{flask.__version__}"
        response.headers["X-App-Environment"] = "development"
    else:
        # --- MODE SÉCURISÉ ---------------------------------------------------
        # On masque la pile technique et on durcit la réponse.
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "script-src 'self' https://cdn.tailwindcss.com https://unpkg.com; "
            "img-src 'self' data:;"
        )
        # Strict-Transport-Security n'a de sens qu'derrière une terminaison TLS
        # (ex. Nginx). Décommenter en production HTTPS :
        # response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    return response


# ---------------------------------------------------------------------
# Décorateurs d'authentification
# ---------------------------------------------------------------------
def authentification_admin_requise(vue):
    """Protège une route en exigeant une session administrateur valide."""
    @wraps(vue)
    def wrapper(*args, **kwargs):
        if not session.get("est_admin"):
            flash("Veuillez vous authentifier pour accéder à cette ressource.", "error")
            return redirect(url_for("admin_login", next=request.path))
        return vue(*args, **kwargs)
    return wrapper


def connexion_requise(vue):
    """
    Protège une route citoyenne (ex. /dashboard) en exigeant qu'un
    usager soit connecté. Ce contrôle d'accès est INDÉPENDANT de
    SECURE_MODE : l'espace personnel d'un usager reste protégé dans
    les deux modes de démonstration.
    """
    @wraps(vue)
    def wrapper(*args, **kwargs):
        if not session.get("usager_id"):
            flash("Veuillez vous connecter pour accéder à votre espace personnel.", "error")
            return redirect(url_for("connexion", next=request.path))
        return vue(*args, **kwargs)
    return wrapper


@app.context_processor
def injecter_usager_courant():
    """Rend l'usager connecté disponible dans tous les templates (navbar)."""
    usager = None
    if session.get("usager_id"):
        usager = db.obtenir_usager_par_id(session["usager_id"])
    return {"usager_courant": usager}


# =======================================================================
# ROUTES PUBLIQUES — Vitrine du portail
# =======================================================================

@app.route("/")
def accueil():
    """Page d'accueil : hero, recherche de démarches, accès rapides."""
    return render_template("index.html", services=SERVICES_RAPIDES)


@app.route("/recherche")
def recherche_demarches():
    """
    Recherche de démarches (filtrage côté serveur, entièrement sûr :
    comparaison de chaînes simple, aucun rendu dynamique de gabarit).
    """
    terme = request.args.get("q", "", type=str).strip()
    resultats = [
        s for s in SERVICES_RAPIDES
        if terme.lower() in s["titre"].lower() or terme.lower() in s["description"].lower()
    ] if terme else SERVICES_RAPIDES
    return render_template("index.html", services=resultats, terme_recherche=terme)


@app.route("/service/<slug>")
def detail_service(slug):
    """Page de détail d'une démarche (contenu statique de démonstration)."""
    service = next((s for s in SERVICES_RAPIDES if s["slug"] == slug), None)
    if service is None:
        return render_template("404.html"), 404
    return render_template("service.html", service=service)


# =======================================================================
# COMPTE CITOYEN — Inscription / Connexion / Déconnexion
# =======================================================================
#
# Module standard, hors périmètre des 2 vulnérabilités pédagogiques.
# Bonnes pratiques appliquées en permanence (voir db.py) :
#   - mots de passe hachés (jamais stockés en clair)
#   - requêtes SQL paramétrées (aucune injection possible)
#   - validation serveur des champs (e-mail, longueur du mot de passe)
# =======================================================================

@app.route("/inscription", methods=["GET", "POST"])
def inscription():
    """Création d'un compte citoyen (usager du portail)."""
    erreurs = []
    valeurs = {"prenom": "", "nom": "", "email": "", "telephone": "", "ville": ""}

    if request.method == "POST":
        valeurs["prenom"] = request.form.get("prenom", "").strip()
        valeurs["nom"] = request.form.get("nom", "").strip()
        valeurs["email"] = request.form.get("email", "").strip()
        valeurs["telephone"] = request.form.get("telephone", "").strip()
        valeurs["ville"] = request.form.get("ville", "").strip()
        mot_de_passe = request.form.get("mot_de_passe", "")
        confirmation = request.form.get("confirmation", "")

        # --- Validation serveur (indépendante de SECURE_MODE) ---------------
        if not valeurs["prenom"] or not valeurs["nom"]:
            erreurs.append("Le prénom et le nom sont obligatoires.")
        if not REGEX_EMAIL.match(valeurs["email"]):
            erreurs.append("Adresse e-mail invalide.")
        elif db.email_deja_utilise(valeurs["email"]):
            erreurs.append("Un compte existe déjà avec cette adresse e-mail.")
        if len(mot_de_passe) < 8:
            erreurs.append("Le mot de passe doit contenir au moins 8 caractères.")
        if mot_de_passe != confirmation:
            erreurs.append("La confirmation ne correspond pas au mot de passe saisi.")

        if not erreurs:
            usager = db.creer_usager(
                prenom=valeurs["prenom"],
                nom=valeurs["nom"],
                email=valeurs["email"],
                telephone=valeurs["telephone"],
                ville=valeurs["ville"],
                mot_de_passe=mot_de_passe,
            )
            flash(
                f"Compte créé avec succès ! Votre numéro d'usager est {usager['numero_usager']}. "
                "Vous pouvez maintenant vous connecter.",
                "success",
            )
            return redirect(url_for("connexion"))

    return render_template("inscription.html", erreurs=erreurs, valeurs=valeurs)


@app.route("/connexion", methods=["GET", "POST"])
def connexion():
    """Connexion d'un usager déjà inscrit."""
    erreur = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        mot_de_passe = request.form.get("mot_de_passe", "")

        usager = db.verifier_identifiants(email, mot_de_passe)
        if usager is not None:
            # On ne stocke que l'identifiant en session (jamais le mot de passe).
            session["usager_id"] = usager["id"]
            flash(f"Bienvenue, {usager['prenom']} !", "success")
            destination = request.args.get("next") or url_for("dashboard")
            return redirect(destination)

        erreur = "Adresse e-mail ou mot de passe incorrect."

    return render_template("connexion.html", erreur=erreur)


@app.route("/deconnexion")
def deconnexion():
    session.pop("usager_id", None)
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("accueil"))


# =======================================================================
# ESPACE CITOYEN — Dashboard (protégé par connexion)
# =======================================================================

@app.route("/dashboard")
@connexion_requise
def dashboard():
    """Tableau de bord citoyen — réservé aux usagers connectés."""
    usager = db.obtenir_usager_par_id(session["usager_id"])
    return render_template(
        "dashboard.html",
        demarches=DASHBOARD_DEMARCHES,
        alertes=DASHBOARD_ALERTES,
        citoyen=usager,
    )


# =======================================================================
# FORMULAIRE D'ASSISTANCE — Point d'entrée de la démonstration SSTI
# =======================================================================

@app.route("/assistance", methods=["GET", "POST"])
def assistance():
    """
    Formulaire de demande d'assistance (accessible sans compte, comme
    un formulaire de contact public).

    C'est ICI que se joue la vulnérabilité A06 (Vulnerable & Outdated
    Components) : le message envoyé par l'utilisateur sert à composer
    une page de confirmation.

    - Mode vulnérable : le message est injecté tel quel dans une chaîne
      passée à render_template_string(). Un utilisateur peut alors
      soumettre par exemple {{ 7*7 }} ou {{ config }} et obtenir
      l'exécution du gabarit côté serveur (SSTI).

    - Mode sécurisé : le message n'est JAMAIS interprété comme un
      gabarit. Il est traité comme une simple donnée, échappée via
      MarkupSafe et affichée dans un template statique (render_template)
      qui ne fait que l'insérer dans le DOM — aucune exécution possible.
    """
    confirmation_html = None

    if request.method == "POST":
        nom = request.form.get("nom", "").strip()
        email = request.form.get("email", "").strip()
        sujet = request.form.get("sujet", "").strip()
        message = request.form.get("message", "").strip()

        if not app.config["SECURE_MODE"]:
            # --- MODE VULNÉRABLE (A06 - SSTI) -----------------------------
            # ⚠️ Ne JAMAIS faire ceci en production : on interpole une
            # entrée utilisateur directement dans un gabarit Jinja2 puis
            # on le RENDU. Le moteur de gabarit exécute alors toute
            # expression Jinja2 contenue dans `message`.
            gabarit_vulnerable = f"""
                <div class="p-4 rounded-xl bg-emerald-50 border border-emerald-200">
                    <p class="font-semibold text-slate-800">Merci {nom}, votre demande a bien été enregistrée.</p>
                    <p class="text-sm text-slate-600 mt-2">Récapitulatif de votre message :</p>
                    <p class="mt-1 italic text-slate-700">{message}</p>
                </div>
            """
            confirmation_html = render_template_string(gabarit_vulnerable)
        else:
            # --- MODE SÉCURISÉ (correctif A06) -----------------------------
            # Le message est traité comme une donnée pure : MarkupSafe
            # l'échappe, puis il est injecté dans un template Jinja
            # STATIQUE (fichier .html) via le contexte de rendu normal,
            # jamais via render_template_string(). Aucune expression
            # Jinja2 saisie par l'utilisateur ne peut donc être évaluée.
            message_nettoye = escape(message)
            nom_nettoye = escape(nom)
            confirmation_html = render_template(
                "_confirmation_assistance.html",
                nom=nom_nettoye,
                message=message_nettoye,
            )

        flash("Votre demande d'assistance a été transmise avec succès.", "success")
        return render_template(
            "assistance.html",
            confirmation_html=confirmation_html,
            nom=nom, email=email, sujet=sujet, message=message,
        )

    return render_template("assistance.html", confirmation_html=None)


# =======================================================================
# ADMINISTRATION — Point d'entrée de la démonstration A05
# =======================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """
    Page de connexion administrateur.

    Utilisée uniquement en mode sécurisé pour protéger
    /admin/system-status. En mode vulnérable, cette page existe mais
    n'est pas requise pour accéder au panneau d'état (voir plus bas).
    """
    erreur = None
    if request.method == "POST":
        utilisateur = request.form.get("utilisateur", "")
        mot_de_passe = request.form.get("mot_de_passe", "")
        if (
            utilisateur == app.config["ADMIN_USERNAME"]
            and mot_de_passe == app.config["ADMIN_PASSWORD"]
        ):
            session["est_admin"] = True
            destination = request.args.get("next") or url_for("admin_system_status")
            return redirect(destination)
        erreur = "Identifiants incorrects."
    return render_template("admin_login.html", erreur=erreur)


@app.route("/admin/logout")
def admin_logout():
    session.pop("est_admin", None)
    return redirect(url_for("accueil"))


@app.route("/admin/system-status")
def admin_system_status():
    """
    Tableau de bord technique interne.

    - Mode vulnérable (A05 - Security Misconfiguration) : la route est
      accessible SANS AUCUNE authentification et affiche des
      informations techniques bavardes (version Python, chemins
      serveur, variables de configuration, liste des routes...).
      C'est exactement le type d'endpoint de debug oublié en
      production qui constitue une mauvaise configuration de sécurité.

    - Mode sécurisé : la route exige une session administrateur valide
      (contrôle d'accès strict) ; à défaut, redirection vers la
      connexion, sans fuite d'information.
    """
    if app.config["SECURE_MODE"] and not session.get("est_admin"):
        flash("Accès restreint : authentification administrateur requise.", "error")
        return redirect(url_for("admin_login", next=request.path))

    uptime = datetime.utcnow() - APP_START_TIME
    informations_techniques = {
        "Nom de l'application": app.config["APP_NAME"],
        "Mode sécurisé actif": app.config["SECURE_MODE"],
        "Mode debug Flask": app.config["DEBUG"],
        "Version Python": sys.version,
        "Plateforme": platform.platform(),
        "Version Flask": flask.__version__,
        "Uptime": str(uptime).split(".")[0],
        "Nombre de routes enregistrées": len(list(app.url_map.iter_rules())),
        "Routes de l'application": sorted(
            f"{r.rule}  [{','.join(sorted(r.methods - {'HEAD', 'OPTIONS'}))}]"
            for r in app.url_map.iter_rules()
        ),
    }
    return render_template(
        "admin_status.html",
        infos=informations_techniques,
        mode_vulnerable=not app.config["SECURE_MODE"],
    )


# =======================================================================
# Gestion des erreurs
# =======================================================================

@app.errorhandler(404)
def page_non_trouvee(_e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    # Serveur de développement uniquement. En production : Gunicorn + Nginx
    # (voir README.md, section « Déploiement Ubuntu »).
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])
