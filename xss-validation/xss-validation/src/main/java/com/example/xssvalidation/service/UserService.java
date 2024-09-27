package com.example.xssvalidation.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.xssvalidation.repository.UserRepository;
import com.example.xssvalidation.model.User;


import jakarta.validation.Valid;
import java.util.List;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User saveUser(@Valid User user) {
        return userRepository.save(user);
    }
}

