package com.example.authservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
@Service
    @Slf4j
public class TokenBlacklistService {

    /**
     * TokenBlacklistService — tracks JWT tokens that have been invalidated by logout.
     *
     * The problem: JWTs are stateless. Even after a user logs out, their token
     * remains cryptographically valid until it expires. Anyone holding that token
     * could still use it. Blacklisting solves this.
     *
     * How it works:
     *   - On logout: store the token's unique ID (jti) + its expiry time
     *   - On every request: JwtAuthFilter checks this store before allowing access
     *   - Scheduled cleanup: expired entries are pruned every hour so memory doesn't grow forever
     *
     * This implementation uses an in-memory ConcurrentHashMap.
     * It's thread-safe and fast, but tokens are lost if the server restarts.
     *
     * For production, replace with Redis:
     *   redisTemplate.opsForValue().set(tokenId, "blacklisted", ttl, TimeUnit.MILLISECONDS);
     */
    
    
        /**
         * ConcurrentHashMap is used instead of HashMap because:
         * - Multiple threads handle requests simultaneously
         * - HashMap is NOT thread-safe — concurrent writes cause data corruption
         * - ConcurrentHashMap handles concurrent reads/writes safely without locking everything
         *
         * Key:   token string (the raw JWT)
         * Value: expiry Date (so we can clean up expired entries)
         */
        private final ConcurrentHashMap<String, Date> blacklist = new ConcurrentHashMap<>();
    
        /**
         * Add a token to the blacklist.
         * Called during logout.
         *
         * @param token      the raw JWT string
         * @param expiration when this token naturally expires (so we can clean it up later)
         */
        public void blacklist(String token, Date expiration) {
            blacklist.put(token, expiration);
            log.info("Token blacklisted. Blacklist size: {}", blacklist.size());
        }
    
        /**
         * Check if a token has been blacklisted.
         * Called by JwtAuthFilter on every incoming request.
         *
         * @param token the raw JWT string
         * @return true if the token is blacklisted (should be rejected)
         */
        public boolean isBlacklisted(String token) {
            return blacklist.containsKey(token);
        }
    
        /**
         * Scheduled cleanup — runs every hour.
         * Removes tokens that have already expired naturally.
         *
         * Why? A blacklisted token that's already expired is harmless
         * (JwtUtil.isTokenValid() would reject it anyway). Keeping it
         * wastes memory. This cleanup prevents unbounded growth.
         *
         * @Scheduled(fixedRate = 3600000) = run every 3,600,000 ms = 1 hour
         */
        @Scheduled(fixedRate = 3600000)
        public void removeExpiredTokens() {
            Date now = new Date();
            int before = blacklist.size();
    
            // removeIf iterates and removes entries where the expiry is in the past
            blacklist.entrySet().removeIf(entry -> entry.getValue().before(now));
    
            int removed = before - blacklist.size();
            if (removed > 0) {
                log.info("Blacklist cleanup: removed {} expired tokens. Remaining: {}",
                    removed, blacklist.size());
            }
        }
    }    

