package com.shimady.auth.repository;

import com.shimady.auth.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.time.Instant;
import java.util.Date;

@Repository
public class JwtProvider {
    @Value("${jwt.token.access.expiration}")
    private Long accessTokenExpiration;

    @Value("${jwt.token.refresh.expiration}")
    private Long refreshTokenExpiration;

    private final Key accessSecret;
    private final Key refreshSecret;

    public JwtProvider(
            @Value("${jwt.token.access.secret}") String accessSecret,
            @Value("${jwt.token.refresh.secret}") String refreshSecret
    ) {
        this.accessSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessSecret));
        this.refreshSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecret));
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiration = now.plusMillis(accessTokenExpiration);

        return Jwts.builder()
                .setSubject(user.getEmail())
                .claim("role", user.getRole())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiration))
                .signWith(accessSecret, SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateRefreshToken(User user) {
        Instant now = Instant.now();
        Instant expiration = now.plusMillis(refreshTokenExpiration);

        return Jwts.builder()
                .setSubject(user.getEmail())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiration))
                .signWith(refreshSecret, SignatureAlgorithm.HS512)
                .compact();
    }

    public boolean validateAccessToken(String token) {
        return validateToken(token, accessSecret);
    }

    public boolean validateRefreshToken(String token) {
        return validateToken(token, refreshSecret);
    }

    //TODO: i'm stupid, so i'm gonna add back the exception handling
    // because handler doesn't work with exceptions thrown in the filter
    private boolean validateToken(String token, Key secret) {
        if (!StringUtils.hasText(token)) {
            return false;
        }
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secret)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (IllegalArgumentException e) {
            throw new JwtException(e.getMessage());
        }
    }

    public String getEmailFromAccessToken(String token) {
        return getEmailFromToken(token, accessSecret);
    }

    public String getEmailFromRefreshToken(String token) {
        return getEmailFromToken(token, refreshSecret);
    }

    private String getEmailFromToken(String token, Key secret) {
        return Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(accessSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
