package com.example.correction_tps.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider =new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(this.userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;

    }

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        return new HttpSessionCsrfTokenRepository();  // Stocke le token CSRF dans la session HTTP
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers(header -> header
                        .contentSecurityPolicy(policy -> policy
                                .policyDirectives("default-src 'self'; script-src 'self';").reportOnly())
                )
                //Réponse Q1
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/superadmin/**").hasRole("SUPER_ADMIN")
                        .requestMatchers("/auth/**", "/register/**").permitAll()
                        .anyRequest().authenticated()
                )
                /*.formLogin(form -> form
                        .loginPage("/auth/login")
                        .loginProcessingUrl( "/auth/login" )
                        .defaultSuccessUrl("/home", true)
                        .permitAll()
                )*/
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository())
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .authenticationProvider((authenticationProvider()))
                .sessionManagement(session -> session
                        .sessionFixation().migrateSession()
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true)

                ).
                //Réponse question 3
                rememberMe(c -> c.tokenValiditySeconds(determineSessionDurationBasedOnRole()));
        ;

        return http.build();
    }
    private String getCurrentUserRole() {
        //Utilise SecurityContextHolder pour récupérer le contexte d'authentification
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            return authentication.getAuthorities().iterator().next().getAuthority();
        }
        return null;
    }

    private int determineSessionDurationBasedOnRole() {
        // Par exemple, vous pouvez configurer des temps d'expiration selon les rôles.
        String role = getCurrentUserRole(); // Méthode qui récupère le rôle de l'utilisateur
        if ("ROLE_SUPER_ADMIN".equals(role)) {
            return 5 * 60;  // 5 minutes pour une session hautement critique
        } else if ("ROLE_ADMIN".equals(role)) {
            return 20 * 60;  // 20 minutes pour une session critique
        } else {
            return 60 * 60;  // 1 heure pour une session normale
        }
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
