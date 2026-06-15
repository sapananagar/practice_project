package com.example.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * DTO = Data Transfer Object.
 * These are "shapes" of data coming IN (requests) and going OUT (responses).
 * We never expose the User entity directly — it might contain sensitive fields.
 */
public class AuthDto {

    // ─── Request DTOs (incoming data) ────────────────────────────────────────

    @Data
    public static class RegisterRequest {
        @NotBlank(message = "First name is required")
        private String firstName;

        @NotBlank(message = "Last name is required")
        private String lastName;

        @Email(message = "Must be a valid email")
        @NotBlank(message = "Email is required")
        private String email;

        @Size(min = 8, message = "Password must be at least 8 characters")
        @NotBlank(message = "Password is required")
        private String password;
    }

    @Data
    public static class LoginRequest {
        @Email(message = "Must be a valid email")
        @NotBlank(message = "Email is required")
        private String email;

        @NotBlank(message = "Password is required")
        private String password;
    }

    @Data
    public static class RefreshTokenRequest {
        @NotBlank(message = "Refresh token is required")
        private String refreshToken;
    }

    // ─── Response DTOs (outgoing data) ───────────────────────────────────────

    @Data
    public static class AuthResponse {
        private String accessToken;
        private String refreshToken;
        private String tokenType = "Bearer";
        private long expiresIn; // seconds until access token expires
        private UserInfo user;

        @Data
        public static class UserInfo {
            private Long id;
            private String email;
            private String firstName;
            private String lastName;
            private String role;
        }
    }

    @Data
    public static class MessageResponse {
        private String message;

        public MessageResponse(String message) {
            this.message = message;
        }
    }
}
