package com.example.xssvalidation.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

@RestController
public class CustomHtmlController {

    @GetMapping("/custom-html")
    @ResponseBody
    public String generateHtml(@RequestParam String userInput, HttpServletResponse response) {
        // Échappement de l'entrée utilisateur pour éviter les attaques XSS
        String sanitizedInput = HtmlUtils.htmlEscape(userInput);

        // Ajout de l'en-tête Content-Security-Policy (CSP)
        response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");

        // Construction de la page HTML sécurisée
        return "<html>" +
                "<head><title>Page sécurisée</title></head>" +
                "<body>" +
                "<h1>Bienvenue sur la page sécurisée !</h1>" +
                "<p>Votre saisie est : " + sanitizedInput + "</p>" +
                "</body>" +
                "</html>";
    }

    @GetMapping("/vulnerable-endpoint")
    @ResponseBody
    public String vulnerableEndpoint(@RequestParam String input) {
        // Aucune protection contre XSS ici, le contenu est injecté directement
        return "<html>" +
                "<head><title>Page vulnérable</title></head>" +
                "<body>" +
                "<h1>Page vulnérable à XSS</h1>" +
                "<p>Input utilisateur : " + input + "</p>" +
                "</body>" +
                "</html>";
    }


}

