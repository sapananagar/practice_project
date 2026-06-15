package com.example.authservice.service;

import com.example.authservice.dto.AuthDto.*;
import com.example.authservice.dto.LogoutRequest;
import com.example.authservice.entity.Role;
import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * AuthService — the brain of our auth service.
 *
 * Handles:
 *   1. register()      — validate → hash password → save user → return tokens
 *   2. login()         — authenticate credentials → return tokens
 *   3. refreshToken()  — validate refresh token → issue new access token
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final TokenBlacklistService tokenBlacklistService;
    /**
     * Register a new user.
     *
     * Steps:
     *   1. Check email isn't already taken
     *   2. Hash the password with BCrypt
     *   3. Save the user to the database
     *   4. Generate and return JWT tokens
     */
    @Transactional // if anything fails, the whole method rolls back
    public AuthResponse register(RegisterRequest request) {
        // 1. Check for duplicate email
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException(
                "Email already registered: " + request.getEmail());
        }

        // 2. Build the user entity
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // HASH the password!
                .role(Role.USER) // default role — change to ADMIN in admin creation flow
                .build();

        // 3. Save to database
        User savedUser = userRepository.save(user);
        log.info("New user registered: {}", savedUser.getEmail());

        // 4. Generate tokens and return response
        return buildAuthResponse(savedUser);
    }

    /**
     * Login an existing user.
     *
     * Steps:
     *   1. AuthenticationManager checks credentials (calls UserDetailsService + BCrypt compare)
     *   2. If credentials are wrong, it throws BadCredentialsException automatically
     *   3. Load the user and generate tokens
     */
    public AuthResponse login(LoginRequest request) {
        // This single line handles credential verification
        // If email or password is wrong, Spring throws BadCredentialsException
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
            )
        );

        // Credentials are correct — load the user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException(
                    "User not found: " + request.getEmail()));

        log.info("User logged in: {}", user.getEmail());
        return buildAuthResponse(user);
    }

    /**
     * Refresh an access token using a valid refresh token.
     *
     * This allows users to stay logged in without re-entering credentials.
     * Refresh tokens are long-lived (7 days); access tokens are short-lived (15 min).
     */
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        // Extract email from the refresh token
        String userEmail = jwtUtil.extractUsername(refreshToken);

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException(
                    "User not found: " + userEmail));

        // Validate the refresh token
        if (!jwtUtil.isTokenValid(refreshToken, user)) {
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }

        // Generate a new access token (refresh token stays the same)
        String newAccessToken = jwtUtil.generateAccessToken(user);

        AuthResponse response = buildAuthResponse(user);
        response.setAccessToken(newAccessToken);
        response.setRefreshToken(refreshToken); // reuse the existing refresh token
        return response;
    }
   public void logout(String accessToken, LogoutRequest request) {
        // Blacklist the access token
        if (accessToken != null && !accessToken.isBlank()) {
            try {
                java.util.Date expiry = jwtUtil.extractExpiration(accessToken);
                tokenBlacklistService.blacklist(accessToken, expiry);
                log.info("Access token blacklisted on logout");
            } catch (Exception e) {
                // Token may already be expired or malformed — log and continue
                log.warn("Could not blacklist access token: {}", e.getMessage());
            }
        }
 
        // Blacklist the refresh token if provided
        if (request != null && request.getRefreshToken() != null
                && !request.getRefreshToken().isBlank()) {
            try {
                java.util.Date expiry = jwtUtil.extractExpiration(request.getRefreshToken());
                tokenBlacklistService.blacklist(request.getRefreshToken(), expiry);
                log.info("Refresh token blacklisted on logout");
            } catch (Exception e) {
                log.warn("Could not blacklist refresh token: {}", e.getMessage());
            }
        }
    }
 

    // ─── Private helpers ──────────────────────────────────────────────────────

    /**
     * Build the standard auth response with both tokens + user info.
     */
    private AuthResponse buildAuthResponse(User user) {
        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        AuthResponse.UserInfo userInfo = new AuthResponse.UserInfo();
        userInfo.setId(user.getId());
        userInfo.setEmail(user.getEmail());
        userInfo.setFirstName(user.getFirstName());
        userInfo.setLastName(user.getLastName());
        userInfo.setRole(user.getRole().name());

        AuthResponse response = new AuthResponse();
        response.setAccessToken(accessToken);
        response.setRefreshToken(refreshToken);
        response.setExpiresIn(jwtUtil.getAccessTokenExpiry() / 1000); // convert ms to seconds
        response.setUser(userInfo);
        return response;
    }
}
