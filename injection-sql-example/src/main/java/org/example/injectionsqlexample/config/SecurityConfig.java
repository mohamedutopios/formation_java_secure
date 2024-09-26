package org.example.injectionsqlexample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Désactiver CSRF pour faciliter les tests avec Postman
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                //.requestMatchers("/api/users/register", "/api/users/login", "/api/users/signin", "/api/users/secure-signin").permitAll() // Permettre l'accès sans authentification à ces endpoints
                                .anyRequest().permitAll()
                )
                .httpBasic(withDefaults()); // Utilisation de l'authentification HTTP Basic

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}