package com.example.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * LogoutRequest — optionally accepts a refresh token to also invalidate it.
 *
 * Why blacklist BOTH tokens on logout?
 * - Access token:  still valid for up to 15 min after logout without blacklisting
 * - Refresh token: could be used to mint new access tokens without blacklisting
 *
 * The access token is read from the Authorization header (handled in AuthService).
 * The refresh token is optionally passed in the request body here.
 */
@Data
public class LogoutRequest {

    /**
     * The refresh token to invalidate.
     * Optional — if not provided, only the access token is blacklisted.
     */
    private String refreshToken;
}