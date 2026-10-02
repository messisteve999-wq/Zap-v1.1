# Zap V1.1

Zap est une application de gestion de demandes de connexion fondée sur le consentement. Elle ne clone pas WhatsApp et ne contourne pas son authentification.

## Contenu
- `android/` : application Android native Java.
- `backend/` : API Node.js/Express + SQLite via `node:sqlite`.

## Backend local (Termux)
```bash
cd backend
npm install
node server.js
```
Test : `curl http://127.0.0.1:3000/api/health`

## Render
Déployer `backend/` comme Web Service Node. Build: `npm install`. Start: `npm start`. Node >= 22.5.
Après déploiement, remplacer `YOUR-ZAP-RENDER-URL.onrender.com` dans `MainActivity.java` par l'URL HTTPS du backend, puis compiler l'APK.

## Flux V1.1
1. Création d'un compte avec numéro + PIN.
2. Connexion par session Bearer de 30 jours.
3. Demande vers un autre numéro déjà inscrit sur Zap.
4. Notification du nombre de demandes en attente.
5. Autoriser / Refuser.
6. Connexion active après autorisation.
7. Révocation possible par l'un ou l'autre participant.

## Limite volontaire
Le numéro WhatsApp d'une personne n'est pas une preuve d'identité. La V1.1 ne prétend donc pas vérifier la propriété d'un compte WhatsApp. Pour une version de production, ajouter une vérification OTP/SMS du numéro et, si une intégration WhatsApp est souhaitée, utiliser uniquement les mécanismes/API officiels applicables.
