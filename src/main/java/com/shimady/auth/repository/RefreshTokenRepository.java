package com.shimady.auth.repository;

import com.shimady.auth.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;

@Slf4j
@Repository
@RequiredArgsConstructor
public class RefreshTokenRepository {
    @Value("${jwt.token.refresh.expiration}")
    private Long refreshTokenExpiration;
    private final static String PREFIX = "refresh-token-";

    private final RedisTemplate<String, String> redisTemplate;

    public void save(String token, String email) {
        log.info("Saving refresh token for user with email: {}", email);
        redisTemplate.opsForValue().set(PREFIX + email, token, refreshTokenExpiration, TimeUnit.MILLISECONDS);
    }

    public String findByEmail(String email) {
        log.info("Finding refresh token for user with email: {}", email);
        if (!redisTemplate.hasKey(PREFIX + email)) {
            throw new ResourceNotFoundException("Refresh token for user with email: " + email + " not found");
        }
        return redisTemplate.opsForValue().get(PREFIX + email);
    }
}
