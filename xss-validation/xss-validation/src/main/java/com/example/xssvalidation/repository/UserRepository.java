package com.example.xssvalidation.repository;


import com.example.xssvalidation.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    // Recherches sécurisées par nom d'utilisateur
    User findByUsername(String username);
}

