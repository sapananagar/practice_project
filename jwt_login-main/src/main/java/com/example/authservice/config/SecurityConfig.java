package com.example.authservice.config;

import com.example.authservice.repository.UserRepository;
import com.example.authservice.security.CustomUserDetailsService;
import com.example.authservice.security.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SecurityConfig — the central Spring Security configuration.
 *
 * Key decisions made here:
 *   1. Which endpoints are public vs protected
 *   2. Stateless session (JWT = no server-side sessions)
 *   3. How to load users from DB
 *   4. Password hashing algorithm (BCrypt)
 *   5. Where to plug in our JwtAuthFilter
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity          // Enables @PreAuthorize on controller methods
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final UserRepository userRepository;
    private final CustomUserDetailsService userDetailsService;
    /**
     * The main security filter chain — defines security rules for HTTP requests.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF — not needed for stateless REST APIs with JWT
            // CSRF protects browser-based form submissions, not Bearer token APIs
            .csrf(AbstractHttpConfigurer::disable)

            // Define which endpoints are public and which require authentication
            .authorizeHttpRequests(auth -> auth
                // Public endpoints — no token needed
                .requestMatchers(
                    "/api/auth/**",  // register, login, refresh
                    "/actuator/**"   // health checks
                ).permitAll()

                // Admin-only endpoint example
                .requestMatchers("/api/admin/**").hasRole("ADMIN")

                // Everything else requires a valid JWT
                .anyRequest().authenticated()
            )

            // STATELESS: each request must include JWT — no server sessions
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Tell Spring Security how to authenticate users
            .authenticationProvider(authenticationProvider())

            // Add our JWT filter BEFORE Spring's default username/password filter
            // This way, JWT authentication is checked first on every request
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * UserDetailsService — tells Spring Security how to load a user by username (email).
     * Called automatically by Spring Security during authentication.
     */
    

    /**
     * AuthenticationProvider — combines UserDetailsService + PasswordEncoder.
     * This is what actually verifies "does this password match the stored hash?"
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /**
     * BCryptPasswordEncoder — hashes passwords with BCrypt algorithm.
     * BCrypt is slow by design (makes brute-force attacks expensive).
     * NEVER store plain text passwords. Always use this to hash before saving.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * AuthenticationManager — the facade that coordinates the authentication process.
     * Injected into AuthService to call authenticate(email, password).
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
