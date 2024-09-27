package com.example.correction_tps.controller;

import com.example.correction_tps.entity.User;
import com.example.correction_tps.service.PasswordService;
import com.example.correction_tps.service.RateLimitService;
import com.example.correction_tps.service.UserDetailServiceImpl;
import com.example.correction_tps.validator.PasswordValidator;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/auth")
public class UserController {

    private final UserDetailServiceImpl userService;

    private final PasswordValidator passwordValidator;
    private final RateLimitService rateLimitService;

    public UserController(UserDetailServiceImpl userService, PasswordValidator passwordValidator, RateLimitService rateLimitService) {
        this.userService = userService;
        this.passwordValidator = passwordValidator;
        this.rateLimitService = rateLimitService;
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user, Model model) {
        if (passwordValidator.validatePassword(user.getPassword(), "highly_critical")) {
            model.addAttribute("error", "Password not valid.");
            return "register";
        }

        if (userService.findByUsername(user.getUsername()) != null) {
            model.addAttribute("error", "Username already exists.");
            return "register";
        }
        if (userService.findByUsername(user.getUsername()) != null) {
            model.addAttribute("error", "Username already exists.");
            return "register";
        }
        userService.registerNewUser(user.getUsername(), user.getPassword());
        return "redirect:/auth/login";
    }

    // Opération normale (changement de mot de passe)
    @PostMapping("/change-password")
    public String changePassword(@RequestParam String username, @RequestParam String oldPassword, @RequestParam String newPassword) {
        if (rateLimitService.allowNormalTransaction(username)) {
            if (userService.changePassword(username, oldPassword, newPassword)) {
                return "Password changed successfully";
            } else {
                return "Failed to change password.";
            }
        } else {
            return "Rate limit exceeded for normal operations. Try again later.";
        }
    }

    // Opération critique (suppression de compte)
    @PostMapping("/delete-account")
    public String deleteAccount(@RequestParam String username) {
        if (rateLimitService.allowCriticalTransaction(username)) {
            userService.deleteAccount(username);
            return "Account deleted successfully";
        } else {
            return "Rate limit exceeded for critical operations. Try again later.";
        }
    }
}
