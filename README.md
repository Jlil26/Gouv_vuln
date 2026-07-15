# Togo-Services — Portail National des Services Publics du Togo

Application de démonstration (Flask + Tailwind) simulant le portail
national des services publics togolais (à la manière de gouv.tg),
conçue pour un **exercice d'audit de sécurité**.

Elle intègre exactement **deux vulnérabilités du Top 10 OWASP 2021**,
activables/désactivables en un clic via une seule variable de
configuration : `SECURE_MODE`.

Un véritable **module de compte citoyen** (inscription, connexion,
déconnexion, espace personnel protégé) a été ajouté. Ce module est
volontairement **hors du périmètre des vulnérabilités pédagogiques** :
il applique en permanence les bonnes pratiques standard (mots de passe
hachés, requêtes SQL paramétrées, contrôle d'accès par session) quel
que soit l'état de `SECURE_MODE`, afin de ne jamais introduire de
troisième vulnérabilité non désirée.

> ⚠️ **Usage strictement pédagogique.** Ne déployez jamais le mode
> vulnérable (`SECURE_MODE=False`) sur un réseau accessible depuis
> Internet. Utilisez une machine virtuelle ou un réseau isolé.

---

## 1. Vulnérabilités intégrées

### A05:2021 — Security Misconfiguration
| | Mode vulnérable (`SECURE_MODE=False`) | Mode sécurisé (`SECURE_MODE=True`) |
|---|---|---|
| En-têtes HTTP | `Server` et `X-Powered-By` exposent la pile technique complète (Werkzeug, Python, Flask) | En-têtes techniques supprimés + ajout de `X-Frame-Options`, `X-Content-Type-Options`, `CSP`, `Referrer-Policy` |
| `/admin/system-status` | Accessible **sans authentification**, affiche la version Python, les routes, le mode debug, etc. | Protégé par une session administrateur (`/admin/login`) |

### A06:2021 — Vulnerable and Outdated Components
| | Mode vulnérable | Mode sécurisé |
|---|---|---|
| `requirements.txt` | Versions volontairement obsolètes (Flask 0.12.2, Jinja2 2.10…) | Voir `requirements-secure.txt` (versions à jour) |
| `/assistance` (formulaire) | Le message est injecté dans une chaîne puis passé à `render_template_string()` → **SSTI** exploitable (essayer `{{ 7*7 }}` ou `{{ config }}`) | Le message est échappé (`markupsafe.escape`) et rendu via un template **statique** (`render_template`) : aucune expression n'est interprétée |

---

## 1 bis. Module de compte citoyen (hors périmètre des vulnérabilités)

| Route | Description |
|---|---|
| `GET/POST /inscription` | Création d'un compte (prénom, nom, e-mail, téléphone, ville, mot de passe) |
| `GET/POST /connexion` | Connexion par e-mail + mot de passe |
| `GET /deconnexion` | Déconnexion (vide la session) |
| `GET /dashboard` | Espace personnel — **protégé**, redirige vers `/connexion` si non authentifié |

Bonnes pratiques appliquées (voir `db.py`), **indépendamment de `SECURE_MODE`** :
- Mots de passe hachés avec `werkzeug.security.generate_password_hash` / vérifiés avec `check_password_hash` — jamais stockés en clair.
- Requêtes SQL **paramétrées** (`?` placeholders) via `sqlite3` — aucune injection SQL possible, y compris en mode vulnérable.
- Validation serveur des champs (format e-mail, longueur du mot de passe ≥ 8 caractères, confirmation, unicité de l'e-mail).
- `/dashboard` protégé par le décorateur `connexion_requise`, actif en permanence (ce contrôle d'accès n'est pas lié à la démonstration A05, qui concerne uniquement `/admin/system-status`).

La base `togo_services.db` (SQLite) est créée automatiquement au premier lancement dans le dossier du projet.

---

## 2. Démonstration « Avant / Après »

Le fichier `config.py` lit `SECURE_MODE` depuis une variable
d'environnement (par défaut `False`). Pour basculer en direct devant
le jury, deux options :

**Option A — variable d'environnement (recommandé, sans redémarrage de code)**
```bash
# Terminal 1 : mode vulnérable
export SECURE_MODE=False
python app.py

# Terminal 2 (après Ctrl+C) : mode sécurisé
export SECURE_MODE=True
python app.py
```

**Option B — fichier `.env`**
```bash
cp .env.example .env
# éditer .env et changer SECURE_MODE=True / False
```

Points de démonstration suggérés :
1. `curl -I http://localhost:5000/` → observer les en-têtes `Server` / `X-Powered-By`.
2. Ouvrir `/admin/system-status` sans être connecté.
3. Sur `/assistance`, envoyer `{{ 7*7 }}` dans le champ message → la confirmation affiche `49` (mode vulnérable) ou le texte brut `{{ 7*7 }}` (mode sécurisé).
4. Basculer `SECURE_MODE=True`, relancer, et répéter les 3 tests précédents pour montrer la remédiation.

---

## 3. Installation locale (développement)

```bash
python3 -m venv venv
source venv/bin/activate

# Pour lancer réellement l'application (Flask 0.12 est trop ancien
# pour être installé/exécuté de façon fiable sur les interpréteurs
# Python récents) :
pip install -r requirements-secure.txt

# `requirements.txt` reste la preuve d'audit de la vulnérabilité A06
# (scanner de dépendances, `pip-audit`, Dependabot...) — il ne doit
# pas nécessairement être installé pour la démonstration.

cp .env.example .env
python app.py
```

L'application est alors disponible sur `http://127.0.0.1:5000`.

---

## 4. Déploiement en production sur Ubuntu (Gunicorn + Nginx)

### 4.1. Préparer le serveur
```bash
sudo apt update && sudo apt install -y python3-venv python3-pip nginx
```

### 4.2. Déployer le code
```bash
sudo mkdir -p /var/www/togo-services
sudo chown $USER:$USER /var/www/togo-services
# copier le contenu du projet dans /var/www/togo-services

cd /var/www/togo-services
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-secure.txt

cp .env.example .env
# éditer .env : SECURE_MODE=True, SECRET_KEY, ADMIN_PASSWORD...
```

### 4.3. Service systemd (Gunicorn)
Créer `/etc/systemd/system/togo-services.service` :

```ini
[Unit]
Description=Togo-Services (Gunicorn)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/togo-services
EnvironmentFile=/var/www/togo-services/.env
ExecStart=/var/www/togo-services/venv/bin/gunicorn \
          --workers 3 \
          --bind unix:/var/www/togo-services/togo-services.sock \
          wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now togo-services
sudo systemctl status togo-services
```

### 4.4. Reverse proxy Nginx
Créer `/etc/nginx/sites-available/togo-services` :

```nginx
server {
    listen 80;
    server_name votre-domaine.exemple;

    location /static/ {
        alias /var/www/togo-services/static/;
        expires 30d;
    }

    location / {
        proxy_pass http://unix:/var/www/togo-services/togo-services.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Masquer la signature de Nginx (durcissement complémentaire)
    server_tokens off;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/togo-services /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 4.5. HTTPS (recommandé)
```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d votre-domaine.exemple
```
Une fois le certificat installé, activer `SESSION_COOKIE_SECURE=True`
dans `.env` et décommenter l'en-tête `Strict-Transport-Security` dans
`app.py` (fonction `gerer_entetes_securite`).

---

## 5. Structure du projet

```
togo-services/
├── app.py                     # Application Flask (routes + logique des 2 vulnérabilités)
├── db.py                      # Module de comptes citoyens (hors périmètre des vulnérabilités)
├── config.py                  # Configuration + bascule SECURE_MODE
├── wsgi.py                    # Point d'entrée Gunicorn
├── requirements.txt           # Dépendances volontairement obsolètes (preuve A06)
├── requirements-secure.txt    # Dépendances à jour (pour exécuter l'app)
├── .env.example                # Variables d'environnement
├── togo_services.db            # Base SQLite des usagers (créée au 1er lancement)
├── static/
│   ├── css/style.css          # Charte graphique vert/jaune/rouge (Togo)
│   └── js/main.js
└── templates/
    ├── base.html               # Layout, navigation, bandeau vert/jaune
    ├── index.html               # Page d'accueil (hero + accès rapides)
    ├── service.html              # Détail d'une démarche
    ├── inscription.html            # Création de compte citoyen
    ├── connexion.html               # Connexion citoyenne
    ├── dashboard.html             # Espace citoyen (cartes, graphique, alertes)
    ├── assistance.html             # Formulaire — point d'entrée SSTI
    ├── _confirmation_assistance.html # Template statique (mode sécurisé)
    ├── admin_login.html            # Connexion administrateur
    ├── admin_status.html           # État système — point d'entrée A05
    └── 404.html
```

---

## 6. Avertissement

Cette application n'est **pas** un service gouvernemental officiel. Elle
a été conçue uniquement à des fins pédagogiques dans le cadre d'un
projet d'audit de sécurité et ne doit pas être utilisée pour traiter de
véritables données personnelles ou administratives.
