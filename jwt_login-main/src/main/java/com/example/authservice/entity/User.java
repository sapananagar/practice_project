package com.example.authservice.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * User entity — stored in the 'users' table.
 *
 * Implements UserDetails so Spring Security can use it directly.
 * This is the standard approach: combine your User entity with UserDetails.
 */
@Entity
@Table(name = "users")
@Data                   // Lombok: generates getters, setters, equals, hashCode, toString
@Builder                // Lombok: enables User.builder().email("...").build()
@NoArgsConstructor      // Lombok: generates no-args constructor (required by JPA)
@AllArgsConstructor     // Lombok: generates all-args constructor (used by @Builder)
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password; // always stored as BCrypt hash — NEVER plain text

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Enumerated(EnumType.STRING) // stores "USER" or "ADMIN" in DB (not 0 or 1)
    @Column(nullable = false)
    private Role role;

    // --- UserDetails interface methods ---
    // Spring Security calls these to check permissions and account status

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // "ROLE_USER" or "ROLE_ADMIN" — Spring Security expects the "ROLE_" prefix
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email; // we use email as the username
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
