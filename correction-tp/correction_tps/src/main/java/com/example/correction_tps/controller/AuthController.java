package com.example.correction_tps.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/login")
    public String loginPage(){
        return "login";
    }


    @GetMapping("/home")
    public String homePage(){
        return "home";
    }

    @GetMapping("/demo")
    public String demoPage(){
        return "demo";
    }


}
