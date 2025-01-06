package com.shimady.auth.service;

import com.shimady.auth.model.Role;
import com.shimady.auth.model.User;
import com.shimady.auth.model.dto.JwtRequest;
import com.shimady.auth.model.dto.JwtResponse;
import com.shimady.auth.model.dto.RefreshJwtRequest;
import com.shimady.auth.model.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserService userService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public UserResponse getCurrentUser() {
        User user = userService.getUserByEmail(getUserEmail());
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getRole().getValue()
        );
    }

    @Transactional
    public JwtResponse signUp(JwtRequest request) {
        log.info("Signing up user with email: {}", request.getEmail());
        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.ROLE_USER);
        userService.saveUser(user);
        return jwtService.generateTokens(user);
    }

    @Transactional(readOnly = true)
    public JwtResponse authenticate(JwtRequest request) {
        log.info("Authenticating user with email: {}", request.getEmail());
        User user = userService.getUserByEmail(request.getEmail());
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }
        return jwtService.generateTokens(user);
    }

    @Transactional
    public JwtResponse refreshToken(RefreshJwtRequest request) {
        return jwtService.refreshToken(request.getRefreshToken());
    }

    protected String getUserEmail() {
        return (String) SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();
    }
}
