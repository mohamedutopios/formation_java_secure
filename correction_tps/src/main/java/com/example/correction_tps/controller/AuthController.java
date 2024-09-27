package com.example.correction_tps.controller;

import com.example.correction_tps.entity.User;
import com.example.correction_tps.service.AttackDetectionService;
import com.example.correction_tps.service.MFAService;
import com.example.correction_tps.service.PasswordService;
import com.example.correction_tps.service.UserDetailServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;



@Controller
@RequestMapping("/auth")
public class AuthController {

    private final UserDetailServiceImpl userService;

    private final MFAService mfaService;

    private final AttackDetectionService attackDetectionService;

    private final AuthenticationManager authenticationManager;


    public AuthController(UserDetailServiceImpl userService, MFAService mfaService, AttackDetectionService attackDetectionService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.mfaService = mfaService;
        this.attackDetectionService = attackDetectionService;
        this.authenticationManager = authenticationManager;

    }

    @GetMapping("/login")
    public String showLoginPage(Model model, @RequestParam(value = "error", required = false) String error) {
        if (error != null) {
            model.addAttribute("error", "Invalid username or password.");
        }
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, HttpServletRequest request, Model model) {

        User user = userService.findByUsername(username);

        // Vérification des connexions suspectes
        if (attackDetectionService.isSuspiciousLogin(user, request)) {
            model.addAttribute("error", "Suspicious login detected. Check your email.");
            return "login";
        }

        try {
            // Authentification manuelle
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // Si l'authentification réussit, générer un OTP pour l'authentification multi-facteurs
            String otp = mfaService.generateOTP(username);
            model.addAttribute("otpSent", true);
            return "otp";  // Redirige vers la page OTP pour validation

        } catch (AuthenticationException e) {
            model.addAttribute("error", "Login failed: " + e.getMessage());
            return "login";
        }
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String username, @RequestParam String otp, Model model) {
        // Vérification OTP
        if (mfaService.validateOTP(username, otp)) {
            return "home";  // Connexion réussie
        } else {
            model.addAttribute("error", "Invalid OTP.");
            return "otp";
        }
    }
}