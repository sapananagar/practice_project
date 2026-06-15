package com.example.authservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.authservice.service.TokenBlacklistService;

import java.io.IOException;

/**
 * JwtAuthFilter — runs ONCE per HTTP request (OncePerRequestFilter).
 *
 * What it does:
 *   1. Reads the "Authorization" header
 *   2. Extracts the JWT from "Bearer <token>"
 *   3. Validates the JWT and loads the user
 *   4. Sets the authentication in Spring Security's context
 *
 * After this filter, Spring Security knows WHO is making the request.
 * If no valid token is found, the request proceeds unauthenticated
 * (Spring Security will then block access to protected endpoints).
 */
@Component
@RequiredArgsConstructor // Lombok: generates constructor for all final fields
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // If no Authorization header or it doesn't start with "Bearer ", skip JWT auth
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the token (everything after "Bearer ")
        final String jwt = authHeader.substring(7);
        String userEmail = null;

        try {
            userEmail = jwtUtil.extractUsername(jwt);
        } catch (Exception e) {
            log.warn("Could not extract username from JWT: {}", e.getMessage());
        }
        if (jwt != null && tokenBlacklistService.isBlacklisted(jwt)) {
            filterChain.doFilter(request, response);
            return;
        }
        // If we got an email AND the user isn't already authenticated in this request
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            if (jwtUtil.isTokenValid(jwt, userDetails)) {
                // Create an authentication token (not a JWT — this is Spring Security's internal token)
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,                          // credentials not needed after authentication
                                userDetails.getAuthorities()   // roles like ROLE_USER, ROLE_ADMIN
                        );

                // Add request details (IP, session) to the authentication
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Tell Spring Security: this user is authenticated for this request
                SecurityContextHolder.getContext().setAuthentication(authToken);
                log.debug("Authenticated user: {}", userEmail);
            }
        }

        // Continue processing the request (go to the next filter or the controller)
        filterChain.doFilter(request, response);
    }
}
