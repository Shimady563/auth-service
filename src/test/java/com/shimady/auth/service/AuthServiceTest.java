package com.shimady.auth.service;

import com.shimady.auth.model.Role;
import com.shimady.auth.model.User;
import com.shimady.auth.model.dto.JwtRequest;
import com.shimady.auth.model.dto.JwtResponse;
import com.shimady.auth.model.dto.RefreshJwtRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    @Mock
    private UserService userService;

    @Mock
    private JwtService jwtService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Spy
    @InjectMocks
    private AuthService authService;

    @Test
    void shouldGetCurrentUser() {
        var user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setPassword("password");
        user.setRole(Role.ROLE_USER);

        given(userService.getUserByEmail(anyString())).willReturn(user);
        willReturn(user.getEmail()).given(authService).getUserEmail();

        var response = authService.getCurrentUser();

        assertNotNull(response);
        assertEquals(user.getId(), response.getId());
        assertEquals(user.getEmail(), response.getEmail());
        assertEquals(user.getRole().getValue(), response.getRole());
        then(userService).should().getUserByEmail(user.getEmail());
    }

    @Test
    void shouldSignUpUser() {
        var request = new JwtRequest();
        request.setEmail("test@example.com");
        request.setPassword("password");
        var user = new User();
        user.setEmail(request.getEmail());
        user.setPassword("encodedPassword");
        user.setRole(Role.ROLE_USER);

        given(passwordEncoder.encode(request.getPassword())).willReturn("encodedPassword");
        given(jwtService.generateTokens(any(User.class))).willReturn(new JwtResponse("token", "refreshToken"));

        var response = authService.signUp(request);

        assertNotNull(response);
        assertEquals("token", response.getAccessToken());
        assertEquals("refreshToken", response.getRefreshToken());
        then(userService).should().saveUser(any(User.class));
    }

    @Test
    void shouldAuthenticateUser() {
        var request = new JwtRequest();
        request.setEmail("test@example.com");
        request.setPassword("password");
        var user = new User();
        user.setId(1L);
        user.setEmail(request.getEmail());
        user.setPassword("encodedPassword");
        user.setRole(Role.ROLE_USER);

        given(userService.getUserByEmail(request.getEmail())).willReturn(user);
        given(passwordEncoder.matches(request.getPassword(), user.getPassword())).willReturn(true);
        given(jwtService.generateTokens(user)).willReturn(new JwtResponse("token", "refreshToken"));

        var response = authService.authenticate(request);

        assertNotNull(response);
        assertEquals("token", response.getAccessToken());
        assertEquals("refreshToken", response.getRefreshToken());
    }

    @Test
    void shouldThrowExceptionWhenUserPasswordIsInvalid() {
        var request = new JwtRequest();
        request.setEmail("test@example.com");
        request.setPassword("wrongPassword");
        var user = new User();
        user.setId(1L);
        user.setPassword("encodedPassword");
        user.setRole(Role.ROLE_USER);

        given(userService.getUserByEmail(request.getEmail())).willReturn(user);
        given(passwordEncoder.matches(request.getPassword(), user.getPassword())).willReturn(false);

        assertThrows(BadCredentialsException.class,
                () -> authService.authenticate(request));
    }

    @Test
    void shouldRefreshToken() {
        var request = new RefreshJwtRequest();
        request.setRefreshToken("refreshToken");

        given(jwtService.refreshToken(request.getRefreshToken())).willReturn(new JwtResponse("newToken", "newRefreshToken"));

        var response = authService.refreshToken(request);

        assertNotNull(response);
        assertEquals("newToken", response.getAccessToken());
        assertEquals("newRefreshToken", response.getRefreshToken());
    }
}
