package com.example.correction_tps.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    // Affiche la page de login
    @GetMapping("/login")
    public String loginPage() {
        return "login";  // Cette vue doit correspondre à un fichier HTML ou Thymeleaf nommé login.html
    }

    // Page d'accueil après succès de la connexion
    @GetMapping("/home")
    public String homePage(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());
        return "home";  // Cette vue doit correspondre à un fichier HTML ou Thymeleaf nommé home.html
    }

    @GetMapping("/demo")
    public String demoPage() {
        return "demo";  // Cette vue doit correspondre à un fichier HTML ou Thymeleaf nommé home.html
    }

}
