package com.shimady.auth.service;

import com.shimady.auth.model.JwtAuthentication;
import com.shimady.auth.model.Role;
import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Service;

@Service
public class JwtUtils {
    public static JwtAuthentication generateAuthentication(Claims claims) {
        JwtAuthentication auth = new JwtAuthentication();
        auth.setEmail(claims.getSubject());
        auth.setRole(Role.valueOf(claims.get("role", String.class)));
        return auth;
    }

    public static String getTokenFromHeader(String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        return header.substring(7);
    }
}
