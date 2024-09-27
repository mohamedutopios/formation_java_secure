package com.example.correction_tps.controller;

import com.example.correction_tps.entity.Role;
import com.example.correction_tps.entity.User;
import com.example.correction_tps.service.SessionService;
import com.example.correction_tps.service.UserDetailServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;



@Controller
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    private UserDetailServiceImpl userService;

    @Autowired
    private SessionService sessionService;

    @GetMapping("")
    public String get() {
        return "home";
    }
    @PostMapping("/assign-role")
    public String assignRole(@RequestParam Long userId, @RequestParam Role role, HttpServletRequest request) {
        User user = userService.findById(userId);
        user.setRole(role);
        userService.save(user);

        // Renouvellement de l'ID de session après modification de rôle
        sessionService.renewSession(request);
        return "redirect:/admin";
    }
}