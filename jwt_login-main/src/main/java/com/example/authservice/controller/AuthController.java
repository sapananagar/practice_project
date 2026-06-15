package com.example.authservice.controller;

import com.example.authservice.dto.AuthDto;
import com.example.authservice.dto.AuthDto.*;
import com.example.authservice.dto.LogoutRequest;
import com.example.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

/**
 * AuthController — exposes the REST API endpoints.
 *
 * All endpoints under /api/auth/** are public (see SecurityConfig).
 * /api/user/me requires a valid JWT.
 * /api/admin/** requires ADMIN role.
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/auth/register
     *
     * Request body:
     *   { "firstName": "John", "lastName": "Doe",
     *     "email": "john@example.com", "password": "secret123" }
     *
     * Response: 201 Created with access + refresh tokens
     */
    @PostMapping("/auth/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request) {
        // @Valid triggers Bean Validation — returns 400 if email/password are invalid
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * POST /api/auth/login
     *
     * Request body: { "email": "john@example.com", "password": "secret123" }
     *
     * Response: 200 OK with access + refresh tokens
     * Error:    401 Unauthorized if credentials are wrong
     */
    @PostMapping("/auth/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * POST /api/auth/refresh
     *
     * Request body: { "refreshToken": "<your-refresh-token>" }
     *
     * Response: 200 OK with a new access token
     * Error:    401 if refresh token is invalid/expired
     */
    @PostMapping("/auth/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }
 @PostMapping("/auth/logout")
    public ResponseEntity<AuthDto.MessageResponse> logout(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody(required = false) LogoutRequest logoutRequest) {
 
        String accessToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);
        }
 
        authService.logout(accessToken, logoutRequest);
        return ResponseEntity.ok(new AuthDto.MessageResponse("Logged out successfully"));
    }
    /**
     * GET /api/user/me
     *
     * Returns the currently authenticated user's info.
     * Requires a valid JWT in the Authorization header.
     *
     * @AuthenticationPrincipal — Spring injects the currently logged-in user
     */
    @GetMapping("/user/me")
    public ResponseEntity<MessageResponse> getCurrentUser(
            @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(
            new MessageResponse("Hello, " + userDetails.getUsername()
                + " — your roles: " + userDetails.getAuthorities()));
    }

    /**
     * GET /api/admin/dashboard
     *
     * Example admin-only endpoint.
     * @PreAuthorize("hasRole('ADMIN')") — rejects with 403 if user isn't ADMIN.
     * (SecurityConfig also enforces this via .requestMatchers("/api/admin/**").hasRole("ADMIN"))
     */
    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MessageResponse> adminDashboard() {
        return ResponseEntity.ok(
            new MessageResponse("Welcome to the admin dashboard!"));
    }
}
