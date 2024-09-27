package com.example.jwtspringsecurity.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class EmailVerificationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

            String path = request.getRequestURI();

        if ("/api/auth/register".equals(path) || "/api/auth/login".equals(path)) {

            if ("POST".equalsIgnoreCase(request.getMethod()) && request.getContentType().contains("application/json")) {
                // Lire le corps de la requête JSON
                ObjectMapper mapper = new ObjectMapper();
                Map<String, Object> jsonMap = mapper.readValue(request.getInputStream(), Map.class);

                String email = (String) jsonMap.get("email");

                if (email == null || !email.endsWith("@gmail.com")) {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Email must be a Gmail address.");
                    return;
                }
            }
            filterChain.doFilter(request, response);
        }
    }
}
