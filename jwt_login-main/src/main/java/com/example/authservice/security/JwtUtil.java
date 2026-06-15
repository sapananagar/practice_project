package com.example.authservice.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JwtUtil — handles everything JWT-related:
 *   1. Generating access tokens
 *   2. Generating refresh tokens
 *   3. Extracting claims (email, expiry, etc.) from tokens
 *   4. Validating tokens
 *
 * JWT structure: header.payload.signature
 *   - Header: algorithm info (e.g., HS256)
 *   - Payload: claims (email, role, issued-at, expiry)
 *   - Signature: HMAC of header + payload, signed with our secret key
 */
@Component
@Slf4j // Lombok: gives us `log.info(...)`, `log.error(...)` etc.
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-token-expiry}")
    private long accessTokenExpiry; // milliseconds

    @Value("${jwt.refresh-token-expiry}")
    private long refreshTokenExpiry; // milliseconds

    // ─── Token Generation ─────────────────────────────────────────────────────

    /**
     * Generate an access token for a user.
     * Access token is short-lived (15 min) and used to access protected APIs.
     */
    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();
        // Add role to the token payload so we can read it without a DB call
        extraClaims.put("role", userDetails.getAuthorities()
                .stream().findFirst()
                .map(Object::toString)
                .orElse("ROLE_USER"));
        return buildToken(extraClaims, userDetails, accessTokenExpiry);
    }

    /**
     * Generate a refresh token for a user.
     * Refresh token is long-lived (7 days) and ONLY used to get new access tokens.
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshTokenExpiry);
    }

    private String buildToken(Map<String, Object> extraClaims,
                              UserDetails userDetails,
                              long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername()) // username = email
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ─── Token Validation ─────────────────────────────────────────────────────

    /**
     * Returns true if the token is valid for this user and not expired.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // ─── Claims Extraction ────────────────────────────────────────────────────

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Generic claim extractor using a Function (Java functional style).
     * Example: extractClaim(token, Claims::getSubject) gets the email.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Convert the secret string into a cryptographic key.
     * Keys.hmacShaKeyFor() ensures the key is long enough for HS256.
     */
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public long getAccessTokenExpiry() {
        return accessTokenExpiry;
    }
}
