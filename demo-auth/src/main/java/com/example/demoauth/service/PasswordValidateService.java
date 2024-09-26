package com.example.demoauth.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PasswordValidateService {

    // Map pour stocker le mot de passe haché et le sel concaténé pour chaque utilisateur
    private Map<String, String> passwordHashes = new HashMap<>();
    private Map<String, Long> lastPasswordChange = new HashMap<>();
    private Map<String, Long> lastActivity = new HashMap<>();
    private Map<String, Boolean> dormantAccounts = new HashMap<>();

    // Durée d'inactivité avant de marquer un compte comme dormant (30 jours)
    private static final long DORMANT_THRESHOLD = 2592000000L; // 30 jours en millisecondes


    public enum Category {
        IMPORTANTE, CRITIQUE, HAUTEMENT_CRITIQUE
    }

    // Fonction pour valider un mot de passe
    public boolean validatePassword(String password, Category category, String username) {
        // Forcer le changement de mot de passe régulièrement
        if (passwordChangedRecently(username)) {
            return false;
        }

        // Vérifier si le mot de passe est trop simple ou non conforme à la catégorie
        if (!isPasswordComplex(password, category)) {
            return false;
        }

        // Si l'utilisateur a un compte dormant
        if (isDormant(username)) {
            return false;
        }

        return true;
    }

    // Forcer l’utilisateur à changer régulièrement de mot de passe
    private boolean passwordChangedRecently(String username) {
        long currentTime = System.currentTimeMillis();
        return lastPasswordChange.containsKey(username) && (currentTime - lastPasswordChange.get(username)) < DORMANT_THRESHOLD; // 30 jours
    }

    // Limiter les rappels de mot de passe fréquents (exemple : 1 fois par jour)
    public boolean canRequestPasswordReset(String username) {
        long currentTime = System.currentTimeMillis();
        return !lastPasswordChange.containsKey(username) || (currentTime - lastPasswordChange.get(username)) > 86400000L; // 1 jour en millisecondes
    }

    // Vérifier si un compte est dormant (inactivité depuis 30 jours)
    public boolean isDormant(String username) {
        long currentTime = System.currentTimeMillis();
        return lastActivity.containsKey(username) && (currentTime - lastActivity.get(username)) > DORMANT_THRESHOLD;
    }

    // Marquer un compte comme dormant
    public void markAsDormantIfInactive(String username) {
        if (isDormant(username)) {
            dormantAccounts.put(username, true);
        }
    }

    // Activer un compte après authentification réussie
    public void activateAccount(String username) {
        dormantAccounts.put(username, false);
        lastActivity.put(username, System.currentTimeMillis()); // Mettre à jour l'activité
    }

    // Mettre à jour la dernière activité à chaque connexion réussie
    public void updateActivity(String username) {
        lastActivity.put(username, System.currentTimeMillis());
    }

    // Ne pas autoriser le changement de mot de passe sans validation du mot de passe actuel
    public boolean validateCurrentPassword(String currentPassword, String username) {
        if (passwordHashes.containsKey(username)) {
            String[] parts = passwordHashes.get(username).split("\\$"); // Diviser sel et hash
            String salt = parts[0];
            String storedHash = parts[1];

            String providedHash = hashPassword(currentPassword, Base64.getDecoder().decode(salt));
            return storedHash.equals(providedHash);
        }
        return false;
    }

    // Ne pas stocker le mot de passe en CLAIR : hash avec un sel et stocker
    private String hashPassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashedPassword = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Créer un nouveau sel pour chaque utilisateur
    private byte[] createSalt() {
        SecureRandom sr;
        try {
            sr = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    // Mise à jour du mot de passe (avec sel et hash concaténé)
    public boolean updatePassword(String oldPassword, String newPassword, String username, Category category) {
        if (validateCurrentPassword(oldPassword, username) && validatePassword(newPassword, category, username)) {
            byte[] salt = createSalt();
            String hash = hashPassword(newPassword, salt);
            // Concaténer le sel et le hash avec un séparateur '$'
            String combined = Base64.getEncoder().encodeToString(salt) + "$" + hash;

            passwordHashes.put(username, combined);
            lastPasswordChange.put(username, System.currentTimeMillis());
            return true;
        }
        return false;
    }

    // Fonction pour la vérification de la complexité du mot de passe
    private boolean isPasswordComplex(String password, Category category) {
        if (category == Category.IMPORTANTE && password.length() < 6) {
            return false;
        } else if (category == Category.CRITIQUE && password.length() < 8) {
            return false;
        } else if (category == Category.HAUTEMENT_CRITIQUE && password.length() < 14) {
            return false;
        }

        // Vérifier la complexité : minuscule, majuscule, chiffre, caractère spécial
        String complexityPattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{6,}$";
        return password.matches(complexityPattern);
    }




















}
