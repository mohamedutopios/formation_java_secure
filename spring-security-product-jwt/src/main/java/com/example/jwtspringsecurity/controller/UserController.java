package com.example.jwtspringsecurity.controller;

import com.example.jwtspringsecurity.dto.BaseResponceDto;
import com.example.jwtspringsecurity.dto.UserLoginDto;
import com.example.jwtspringsecurity.service.UserService;
import com.example.jwtspringsecurity.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

// Annotation indiquant que cette classe est un contrôleur REST.
@RestController
public class UserController {

    // Injection automatique du service UserService.
    @Autowired
    UserService userService;

    // Endpoint POST pour l'enregistrement d'un nouvel utilisateur.
    @PostMapping("/api/auth/register")
    public BaseResponceDto registerUser(@RequestBody User newUser){
        // Appel du service pour créer un nouvel utilisateur.
        if(userService.createUser(newUser)){
            // En cas de succès, renvoyer une réponse indiquant le succès.
            return new BaseResponceDto("success");
        }else {
            // En cas d'échec, renvoyer une réponse indiquant l'échec.
            return new BaseResponceDto("failed");
        }
    }

    // Endpoint POST pour la connexion d'un utilisateur.
    @PostMapping("/api/auth/login")
    public BaseResponceDto loginUser(@RequestBody UserLoginDto loginDetails){
        // Vérifier si l'email de l'utilisateur existe.
        if(userService.checkUserNameExists(loginDetails.getEmail())){
            // Vérifier si le mot de passe correspond à l'email.
            if(userService.verifyUser(loginDetails.getEmail(), loginDetails.getPassword())){
                // Si la vérification est réussie, préparer les données de la réponse.
                Map<String, Object> data = new HashMap<>();
                // Générer un token JWT et l'ajouter aux données.
                data.put("token", userService.generateToken(loginDetails.getEmail(), loginDetails.getPassword()));
                // Renvoyer une réponse avec les données du token.
                return new BaseResponceDto("success", data);
            }else {
                // Renvoyer une réponse en cas de mot de passe incorrect.
                return new BaseResponceDto("wrong password");
            }
        }else {
            // Renvoyer une réponse si l'utilisateur n'existe pas.
            return new BaseResponceDto("user not exist");
        }
    }

    
}

