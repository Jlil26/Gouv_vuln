# -*- coding: utf-8 -*-
"""Point d'entrée WSGI pour un serveur de production (Gunicorn).

Exemple d'utilisation :
    gunicorn --workers 3 --bind 127.0.0.1:8000 wsgi:app
"""

from app import app

if __name__ == "__main__":
    app.run()
