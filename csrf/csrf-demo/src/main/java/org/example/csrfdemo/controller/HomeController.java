package org.example.csrfdemo.controller;


import org.example.csrfdemo.model.Message;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @PostMapping("/message")
    public String postMessage(Message message, Model model) {
        model.addAttribute("message", message);
        return "message";
    }
}
