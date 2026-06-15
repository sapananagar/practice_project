package com.example.authservice.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * GlobalExceptionHandler — catches exceptions and returns clean JSON error responses.
 *
 * Without this, Spring returns ugly HTML error pages or stack traces.
 * With this, the client always gets:
 *   { "status": 400, "error": "Bad Request", "message": "...", "timestamp": "..." }
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Handles @Valid validation failures (e.g., blank email, short password).
     * Returns 400 with a map of field → error message.
     *
     * Example response:
     * {
     *   "status": 400,
     *   "errors": {
     *     "email": "Must be a valid email",
     *     "password": "Password must be at least 8 characters"
     *   }
     * }
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationErrors(
            MethodArgumentNotValidException ex) {
        Map<String, String> fieldErrors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            fieldErrors.put(fieldName, errorMessage);
        });

        return ResponseEntity.badRequest().body(Map.of(
            "status", 400,
            "error", "Validation failed",
            "errors", fieldErrors,
            "timestamp", LocalDateTime.now().toString()
        ));
    }

    /**
     * Handles wrong email or password during login.
     * Returns 401 Unauthorized.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(
            BadCredentialsException ex) {
        log.warn("Failed login attempt: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
            "status", 401,
            "error", "Unauthorized",
            "message", "Invalid email or password",
            "timestamp", LocalDateTime.now().toString()
        ));
    }

    /**
     * Handles user not found.
     * Returns 404 Not Found.
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUserNotFound(
            UsernameNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
            "status", 404,
            "error", "Not Found",
            "message", ex.getMessage(),
            "timestamp", LocalDateTime.now().toString()
        ));
    }

    /**
     * Handles business rule violations (e.g., duplicate email on register).
     * Returns 409 Conflict.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(
            IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
            "status", 409,
            "error", "Conflict",
            "message", ex.getMessage(),
            "timestamp", LocalDateTime.now().toString()
        ));
    }

    /**
     * Catch-all for unexpected errors.
     * Returns 500 — but never expose the actual error message in production!
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericError(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
            "status", 500,
            "error", "Internal Server Error",
            "message", "An unexpected error occurred. Please try again.",
            "timestamp", LocalDateTime.now().toString()
        ));
    }
}
