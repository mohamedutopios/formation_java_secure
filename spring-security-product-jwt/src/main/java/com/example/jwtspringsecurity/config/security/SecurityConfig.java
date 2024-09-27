package com.example.jwtspringsecurity.config.security;

import com.example.jwtspringsecurity.config.jwt.JwtAuthenticationEntryPoint;
import com.example.jwtspringsecurity.config.jwt.JwtRequestFilter;

import com.example.jwtspringsecurity.filter.EmailVerificationFilter;
import com.example.jwtspringsecurity.service.UserService;

import java.beans.Customizer;
import java.util.Arrays;
import java.util.Collections;

import jakarta.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


// Classe de configuration pour la sécurité de l'application.
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Injection des dépendances pour le service utilisateur et le point d'entrée d'authentification JWT.
    private final UserService userService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    // Constructeur pour initialiser les services injectés.
    public SecurityConfig(UserService userService, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint) {
        this.userService = userService;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    }

    @Bean
    public EmailVerificationFilter emailVerificationFilter(){
        return new EmailVerificationFilter();
    }

    // Bean pour configurer la chaîne de filtres de sécurité.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Désactiver CSRF (Cross-Site Request Forgery) pour les services REST, car ils utilisent des tokens plutôt que des cookies pour l'authentification.
                .csrf(csrf -> csrf.disable())

                // Configurer CORS (Cross-Origin Resource Sharing) en utilisant la source de configuration définie dans une autre méthode.
                // Cela permet de contrôler comment les ressources peuvent être partagées entre différents domaines/origines.
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Configurer la gestion de la session pour être sans état, ce qui est typique pour les API REST qui utilisent des tokens (comme JWT) pour l'authentification.
                // Cela signifie que le serveur ne maintiendra pas d'état de session entre les requêtes.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))


                // Configurer l'autorisation des requêtes HTTP :
                .authorizeHttpRequests(authz -> authz
                        // Permettre à tous les utilisateurs d'accéder aux endpoints commençant par "/api/auth/**" sans authentification.
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/products").hasAnyRole("USER","ADMIN")
                        .requestMatchers("/api/products/admin/**").hasRole("ADMIN")
                        // Exiger l'authentification pour toutes les autres requêtes qui n'ont pas été matchées par les règles ci-dessus.
                        .anyRequest().authenticated())

                // Configurer le traitement des exceptions pour utiliser le point d'entrée d'authentification JWT personnalisé.
                // Cela est utilisé pour envoyer une réponse d'erreur appropriée si l'authentification échoue.
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(jwtAuthenticationEntryPoint))

                // Ajouter un filtre personnalisé (JwtRequestFilter dans cet exemple) avant le filtre d'authentification par nom d'utilisateur et mot de passe.
                // Ce filtre vérifie la présence d'un JWT valide dans les requêtes et l'utilise pour l'authentification.
                .addFilterBefore(emailVerificationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

                // Construire et retourner la chaîne de filtres de sécurité configurée.
        return http.build();

    }



    // Injection de la configuration d'authentification.
    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    // Bean pour obtenir le gestionnaire d'authentification.
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        // Obtention du gestionnaire d'authentification à partir de la configuration.
        return authenticationConfiguration.getAuthenticationManager();
    }

    // Bean pour le filtre d'authentification JWT.
    @Bean
    public JwtRequestFilter jwtAuthenticationFilter() {
        // Création d'un nouveau filtre avec le service utilisateur.
        return new JwtRequestFilter(userService);
    }

    // Bean pour le chiffrement des mots de passe.
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Utilisation de BCrypt pour le chiffrement des mots de passe.
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Collections.singletonList("http://localhost:3000")); // Permettre l'accès pour un appel depuis http://localhost:3000
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")); // Permettre toutes les méthodes
        configuration.setAllowedHeaders(Arrays.asList("*")); // Permettre tous les headers
        configuration.setAllowCredentials(true); // Important pour les cookies, l'autorisation, etc.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Appliquer cette configuration à tous les chemins
        return source;
    }


}

