package com.shimady.auth.controller;

import com.shimady.auth.model.dto.JwtRequest;
import com.shimady.auth.model.dto.JwtResponse;
import com.shimady.auth.model.dto.RefreshJwtRequest;
import com.shimady.auth.model.dto.UserResponse;
import com.shimady.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @Secured({"ROLE_USER", "ROLE_ADMIN"})
    @GetMapping("/me")
    public UserResponse getCurrentUser() {
        return authService.getCurrentUser();
    }

    @PostMapping("/signup")
    public JwtResponse signUp(@RequestBody JwtRequest request) {
        return authService.signUp(request);
    }

    @PostMapping("/login")
    public JwtResponse signIn(@RequestBody JwtRequest request) {
        return authService.authenticate(request);
    }

    @PostMapping("/refresh")
    public JwtResponse refreshToken(@RequestBody RefreshJwtRequest request) {
        return authService.refreshToken(request);
    }
}
