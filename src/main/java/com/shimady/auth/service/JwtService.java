package com.shimady.auth.service;

import com.shimady.auth.model.User;
import com.shimady.auth.model.dto.JwtResponse;
import com.shimady.auth.repository.JwtProvider;
import com.shimady.auth.repository.RefreshTokenRepository;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtProvider provider;
    private final RefreshTokenRepository tokenRepository;
    private final UserService userService;

    @Transactional
    public JwtResponse generateTokens(User user) {
        log.info("Generating tokens for user with email: {}", user.getEmail());
        String refreshToken = provider.generateRefreshToken(user);
        tokenRepository.save(refreshToken, user.getEmail());
        return new JwtResponse(
                provider.generateAccessToken(user),
                refreshToken
        );
    }

    @Transactional(readOnly = true)
    public JwtResponse refreshToken(String refreshToken) {
        log.info("Refreshing access token");
        if (!provider.validateRefreshToken(refreshToken)) {
            throw new JwtException("Invalid refresh token");
        }

        User user = userService.getUserByEmail(provider.getEmailFromRefreshToken(refreshToken));
        String storedToken = tokenRepository.findByEmail(user.getEmail());

        if (!refreshToken.equals(storedToken)) {
            throw new JwtException("Invalid refresh token for user with email: " + user.getEmail());
        }

        return new JwtResponse(
                provider.generateAccessToken(user),
                refreshToken
        );
    }
}
