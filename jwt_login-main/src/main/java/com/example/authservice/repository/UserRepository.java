package com.example.authservice.repository;

import com.example.authservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * UserRepository — handles all database operations for User.
 *
 * By extending JpaRepository, we get these methods FOR FREE:
 *   - save(user)         → INSERT or UPDATE
 *   - findById(id)       → SELECT by primary key
 *   - findAll()          → SELECT all users
 *   - delete(user)       → DELETE
 *   - existsById(id)     → check if exists
 *
 * We only need to define custom queries here.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Spring Data JPA auto-generates this SQL:
     *   SELECT * FROM users WHERE email = ?
     *
     * Returns Optional<User> — forces callers to handle "not found" case.
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if a user with the given email already exists.
     * Useful during registration to prevent duplicates.
     */
    boolean existsByEmail(String email);
}
