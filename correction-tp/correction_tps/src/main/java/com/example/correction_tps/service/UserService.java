package com.example.correction_tps.service;

import com.example.correction_tps.entity.User;
import com.example.correction_tps.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
@Service
public class UserService {

    private final UserRepository userRepository;

    private final PasswordService passwordService;

    public UserService(UserRepository userRepository, PasswordService passwordService) {
        this.userRepository = userRepository;
        this.passwordService = passwordService;
    }

    public boolean changePassword(Long userId, String newPassword) {
        User user = userRepository.findById(userId).orElseThrow();

        // Check if the password was changed in the last 30 days
        if (user.getPasswordChangedDate().isAfter(LocalDate.now().minusDays(30))) {
            throw new IllegalArgumentException("You must wait 30 days before changing the password again.");
        }

        // Check if the new password matches any of the last 5 passwords
        List<String> oldPasswords = user.getOldPasswords();
        for (String oldPassword : oldPasswords) {
            if (passwordService.matchesPassword(newPassword, oldPassword)) {
                throw new IllegalArgumentException("You cannot reuse an old password.");
            }
        }

        // Add the current password to the password history
        oldPasswords.add(user.getPassword());
        if (oldPasswords.size() > 5) {
            oldPasswords.remove(0);  // Keep only the last 5 passwords
        }

        // Update the new password
        user.setPassword(passwordService.hashPassword(newPassword));
        user.setPasswordChangedDate(LocalDate.now());
        userRepository.save(user);
        return true;
    }

    public void login(User user) {
        if (user.isSleepy()) {
            throw new IllegalArgumentException("Your account is inactive. Please contact support.");
        }

        user.setLastLogin(LocalDate.now());
        userRepository.save(user);
    }
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public void save(User user) {
        userRepository.save(user);
    }
}
