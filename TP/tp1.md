

### TP 1 : **Développement d'un système sécurisé d'authentification et de gestion des mots de passe avec multi-facteurs en Java**

#### Contexte :
Vous développez un système d'authentification sécurisé pour une application sensible. L’objectif est d’implémenter un système de gestion des mots de passe avec des règles de complexité, un suivi des tentatives de connexion, et un système d’authentification multi-facteurs via une **émulation** d’envoi de code OTP.

#### Exigences :
1. **Catégorisation des mots de passe selon le niveau de criticité** :
   - **Important** : minimum 6 caractères.
   - **Critique** : minimum 8 caractères avec une minuscule, majuscule, chiffre et caractère spécial.
   - **Hautement critique** : minimum 14 caractères, inclure plusieurs facteurs (authentification multi-facteurs).

2. **Complexité des mots de passe** :
   - Forcer l'utilisation de lettres, chiffres, et caractères spéciaux.
   - Interdire l’utilisation de séquences simples (`123`, `AAA`).
   - Empêcher l’utilisation de mots de passe issus d'un dictionnaire.

3. **Gestion des anciens mots de passe et des rappels** :
   - Forcer le changement de mot de passe tous les 30 jours.
   - Ne pas autoriser la réutilisation des 5 derniers mots de passe.
   - Limiter les rappels de mot de passe à une fois toutes les 24 heures.

4. **Gestion des accès dormants** :
   - Marquer un compte comme dormant après 30 jours d'inactivité.

5. **Authentification multi-facteurs (MFA)** :
   - Pour les utilisateurs accédant à des informations hautement critiques, mettre en place un système d’authentification multi-facteurs.
   - **Émuler** l’envoi d'un code OTP qui est affiché dans la console.

6. **Protection contre les attaques par brute force** :
   - Verrouiller un compte après 5 tentatives échouées et le débloquer après 15 minutes.

---

### Explication de l'OTP Émulé :

- L’**OTP** est un code temporaire généré et **émulé** en affichant simplement le code dans la console au lieu de l'envoyer par SMS.
- Ce code est ensuite utilisé par l'utilisateur pour finaliser la connexion.
- Vous pouvez tester cette partie sans avoir besoin d'une véritable infrastructure