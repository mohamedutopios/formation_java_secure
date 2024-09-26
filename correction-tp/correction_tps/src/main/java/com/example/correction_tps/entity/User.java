package com.example.correction_tps.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String password;  // Hashed with BCrypt

    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> oldPasswords;  // Store hashed old passwords

    private LocalDate passwordChangedDate;

    private LocalDate lastLogin;
    private LocalDateTime lockTime;
    private int failedAttempts;
    private boolean locked;
    public boolean isSleepy() {
        return lastLogin != null && lastLogin.isBefore(LocalDate.now().minusDays(30));
    }


    public void incrementFailedAttempts() {
        this.failedAttempts++;
        if (this.failedAttempts >= 5) {
            this.locked = true;
            this.lockTime = LocalDateTime.now();
        }
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
        this.locked = false;
    }

    public boolean isLocked() {
        if (this.locked && this.lockTime.isBefore(LocalDateTime.now().minusMinutes(15))) {
            resetFailedAttempts();
            return false;  // Unlock account after 15 minutes
        }
        return this.locked;
    }
}
