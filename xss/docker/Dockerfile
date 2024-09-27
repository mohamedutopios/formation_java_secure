# Utiliser une image de base Python
FROM python:3.9-slim

# Installer Flask
RUN pip install flask

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers de l'application
COPY app.py /app

# Exposer le port de l'application
EXPOSE 5000

# Lancer l'application
CMD ["python", "app.py"]
