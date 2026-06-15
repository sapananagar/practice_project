package com.example.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Auth Service.
 *
 * @SpringBootApplication combines:
 *   - @Configuration       (this class defines beans)
 *   - @EnableAutoConfiguration (Spring Boot magic: auto-configures based on classpath)
 *   - @ComponentScan       (scans this package and subpackages for @Component, @Service, etc.)
 */
@SpringBootApplication
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
        System.out.println("""
            
            ✅ Auth Service started! (PostgreSQL)
            
            Endpoints:
              POST /api/auth/register   — create a new account
              POST /api/auth/login      — get JWT tokens
              POST /api/auth/refresh    — refresh access token
              GET  /api/user/me         — get current user (requires JWT)
              GET  /api/admin/dashboard — admin only (requires JWT + ADMIN role)
            """);
    }
}
