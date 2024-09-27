package com.example.correction_tps.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final UserDetailsService userDetailsService;
    // Le service `UserDetailsService` est utilisé pour récupérer les informations des utilisateurs pour l'authentification.

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }


    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider =new DaoAuthenticationProvider();
        // Création d'un fournisseur d'authentification basé sur les informations des utilisateurs stockées dans la base de données (Dao).

        authProvider.setUserDetailsService(this.userDetailsService);
        // Définit le service `UserDetailsService` pour charger les détails des utilisateurs lors de l'authentification.

        authProvider.setPasswordEncoder(passwordEncoder());
        // Définit le `PasswordEncoder` pour hacher et vérifier les mots de passe. Ici, `BCryptPasswordEncoder` sera utilisé.

        return authProvider;
        // Retourne l'instance du fournisseur d'authentification configuré.
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
        // Crée un `PasswordEncoder` qui utilise l'algorithme BCrypt pour hacher les mots de passe.
        // BCrypt est recommandé pour sa sécurité dans le hachage des mots de passe.
    }


    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        return new HttpSessionCsrfTokenRepository();

    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // Configuration principale de la chaîne de filtres de sécurité pour les requêtes HTTP.

        http
                .headers(header -> header
                        .contentSecurityPolicy(policy -> policy
                                .policyDirectives("default-src 'self'; script-src 'self';").reportOnly())
                )
                // Configure les en-têtes HTTP pour inclure une politique de sécurité du contenu (CSP).
                // La CSP spécifie les sources de contenu autorisées (par exemple, les scripts ne peuvent être chargés que depuis 'self').

                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/auth/**", "/login", "/public/**", "/demo").permitAll()
                        .anyRequest().authenticated()
                )
                // Autorise l'accès libre à certaines routes spécifiques (comme les endpoints d'authentification et les ressources publiques).
                // Toutes les autres requêtes nécessitent une authentification.

                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/home", true)
                        .permitAll()
                )
                // Configure la page de connexion personnalisée à "/login".
                // Après une connexion réussie, l'utilisateur est redirigé vers "/home".
                // L'accès à la page de connexion est autorisé à tout le monde.

                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository())
                )
                // Active la protection CSRF en utilisant le `CsrfTokenRepository` qui stocke le token dans la session HTTP.

                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                // Configure la déconnexion à l'URL "/logout". Après la déconnexion, l'utilisateur est redirigé vers "/login?logout".
                // Tout le monde a le droit de se déconnecter.

                .authenticationProvider((authenticationProvider()))
                // Définit le fournisseur d'authentification personnalisé configuré avec `DaoAuthenticationProvider`.

                .sessionManagement(session -> session
                                .sessionFixation().migrateSession()
                                // Empêche la réutilisation de l'ID de session après la connexion (mitigation des attaques de fixation de session).

                                .maximumSessions(1)
                                // Limite le nombre de sessions actives par utilisateur à une seule session.

                                .maxSessionsPreventsLogin(true)
                        // Empêche l'utilisateur de se connecter à une nouvelle session tant qu'il est déjà connecté sur une session active.

                )
        ;

        return http.build();
        // Construit et retourne l'instance de la chaîne de filtres de sécurité configurée.
    }





}
