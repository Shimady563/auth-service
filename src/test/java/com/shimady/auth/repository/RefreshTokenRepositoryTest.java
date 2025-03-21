package com.shimady.auth.repository;

import com.shimady.auth.exception.ResourceNotFoundException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.data.redis.core.RedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Testcontainers
public class RefreshTokenRepositoryTest {
    @Container
    @ServiceConnection(name = "redis")
    private static final GenericContainer<?> REDIS_CONTAINER =
            new GenericContainer<>(DockerImageName.parse("redis:alpine")).withExposedPorts(6379);
    @Container
    @ServiceConnection(name = "redis")
    private static final PostgreSQLContainer<?> POSTGRES_CONTAINER =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:alpine")).withDatabaseName("auth");

    private final static String PREFIX = "refresh-token-";

    @Autowired
    private RedisTemplate<Object, Object> redisTemplate;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Test
    public void testSave() {
        var newToken = "newToken";
        var email = "newEmail";

        refreshTokenRepository.save(newToken, email);

        String foundToken = refreshTokenRepository.findByEmail(email);

        assertNotNull(foundToken);
        assertEquals(newToken, foundToken);
    }

    @Test
    public void testFindByEmailFailure() {
        assertThrows(ResourceNotFoundException.class,
                () -> refreshTokenRepository.findByEmail("non existing"));
    }
}
