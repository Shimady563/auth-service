package com.shimady.auth.service;

import com.shimady.auth.model.User;
import com.shimady.auth.repository.JwtProvider;
import com.shimady.auth.repository.RefreshTokenRepository;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {
    @Mock
    private JwtProvider provider;

    @Mock
    private RefreshTokenRepository tokenRepository;

    @Mock
    private UserService userService;

    @InjectMocks
    private JwtService jwtService;

    @Test
    void shouldGenerateTokens() {
        var user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setPassword("password");
        var refreshToken = "refreshToken";
        var accessToken = "accessToken";

        given(provider.generateRefreshToken(user)).willReturn(refreshToken);
        given(provider.generateAccessToken(user)).willReturn(accessToken);

        var response = jwtService.generateTokens(user);

        assertNotNull(response);
        assertEquals(accessToken, response.getAccessToken());
        assertEquals(refreshToken, response.getRefreshToken());
        then(tokenRepository).should().save(refreshToken, user.getEmail());
    }

    @Test
    void shouldRefreshToken() {
        var user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setPassword("password");
        var refreshToken = "refreshToken";
        var newAccessToken = "newAccessToken";

        given(provider.validateRefreshToken(refreshToken)).willReturn(true);
        given(provider.getEmailFromRefreshToken(refreshToken)).willReturn(user.getEmail());
        given(userService.getUserByEmail(user.getEmail())).willReturn(user);
        given(tokenRepository.findByEmail(user.getEmail())).willReturn(refreshToken);
        given(provider.generateAccessToken(user)).willReturn(newAccessToken);

        var response = jwtService.refreshToken(refreshToken);

        assertNotNull(response);
        assertEquals(newAccessToken, response.getAccessToken());
        assertEquals(refreshToken, response.getRefreshToken());
    }

    @Test
    void shouldThrowExceptionWhenRefreshTokenIsInvalid() {
        var invalidToken = "invalidToken";
        given(provider.validateRefreshToken(invalidToken)).willReturn(false);

        assertThrows(JwtException.class,
                () -> jwtService.refreshToken(invalidToken));
    }

    @Test
    void shouldThrowExceptionWhenRefreshTokenDoesNotMatchStoredToken() {
        var user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setPassword("password");
        var refreshToken = "refreshToken";

        given(provider.validateRefreshToken(refreshToken)).willReturn(true);
        given(provider.getEmailFromRefreshToken(refreshToken)).willReturn(user.getEmail());
        given(userService.getUserByEmail(user.getEmail())).willReturn(user);
        given(tokenRepository.findByEmail(user.getEmail())).willReturn("differentToken");

        assertThrows(JwtException.class,
                () -> jwtService.refreshToken(refreshToken));
    }
}

