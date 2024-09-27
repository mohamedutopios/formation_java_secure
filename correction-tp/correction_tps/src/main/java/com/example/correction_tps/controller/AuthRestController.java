package com.example.correction_tps.controller;

import com.example.correction_tps.entity.User;
import com.example.correction_tps.service.MFAService;
import com.example.correction_tps.service.PasswordService;
import com.example.correction_tps.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/auth")
public class AuthRestController {

   /* private final UserService userService;
    private final PasswordService passwordService;
    private final MFAService mfaService;  // Ajout du service MFA

    public AuthRestController(UserService userService, PasswordService passwordService, MFAService mfaService) {
        this.userService = userService;
        this.passwordService = passwordService;
        this.mfaService = mfaService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password, @RequestParam(required = false) String otp) {
        User user = userService.findByUsername(username);

        if (user == null || user.isLocked()) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        if (!passwordService.matchesPassword(password, user.getPassword())) {
            user.incrementFailedAttempts();  // Augmenter les tentatives échouées si le mot de passe est incorrect
            userService.save(user);

            if (user.isLocked()) {
                return new ResponseEntity<>("Account locked due to failed login attempts", HttpStatus.LOCKED);
            }

            return new ResponseEntity<>("Invalid credentials", HttpStatus.UNAUTHORIZED);
        }

        // Si l'OTP n'est pas encore soumis
        if (otp == null) {
            // Générer un OTP et l'envoyer à l'utilisateur (simulé)
            String generatedOtp = mfaService.generateOTP(username);
            return new ResponseEntity<>("OTP has been sent. Please verify.", HttpStatus.OK);
        }

        // Validation de l'OTP
        if (!mfaService.validateOTP(username, otp)) {
            return new ResponseEntity<>("Invalid OTP", HttpStatus.FORBIDDEN);
        }

        // Authentification réussie après validation de l'OTP
        user.resetFailedAttempts();
        userService.save(user);
        return new ResponseEntity<>("Login successful", HttpStatus.OK);
    }*/
}
