package com.example.correction_tps.validator;

import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
public class PasswordValidator {

    private static final String SIMPLE_PATTERN = "^.{6,}$"; // Important
    private static final String CRITICAL_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"; // Critical
    private static final String HIGHLY_CRITICAL_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{14,}$"; // Highly Critical
    private static final String[] DICTIONARY_WORDS = {"password", "123456", "qwerty", "admin"};

    public static boolean validatePassword(String password, String level) {
        // Check for dictionary words or simple sequences
        if (containsDictionaryWord(password) || containsSimpleSequence(password)) {
            return false;
        }

        // Validate based on criticality level
        switch (level) {
            case "important":
                return Pattern.matches(SIMPLE_PATTERN, password);
            case "critical":
                return Pattern.matches(CRITICAL_PATTERN, password);
            case "highly_critical":
                return Pattern.matches(HIGHLY_CRITICAL_PATTERN, password);
            default:
                return false;
        }
    }

    private static boolean containsSimpleSequence(String password) {
        return password.matches(".*(123|AAA|abc|qwerty).*");
    }

    private static boolean containsDictionaryWord(String password) {
        for (String word : DICTIONARY_WORDS) {
            if (password.toLowerCase().contains(word)) {
                return true;
            }
        }
        return false;
    }
}
