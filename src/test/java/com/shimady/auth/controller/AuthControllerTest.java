package com.shimady.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shimady.auth.TestSecurityConfig;
import com.shimady.auth.model.dto.JwtRequest;
import com.shimady.auth.model.dto.JwtResponse;
import com.shimady.auth.model.dto.RefreshJwtRequest;
import com.shimady.auth.model.dto.UserResponse;
import com.shimady.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.BDDMockito.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(TestSecurityConfig.class)
class AuthControllerTest {
    @MockitoBean
    private AuthService authService;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser(roles = {"USER", "ADMIN"})
    void shouldGetCurrentUser() throws Exception {
        var userResponse = new UserResponse(1L, "test@example.com", "ROLE_USER");

        given(authService.getCurrentUser()).willReturn(userResponse);

        mockMvc.perform(get("/me"))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userResponse)));
    }

    @Test
    @WithAnonymousUser
    public void shouldNotGetCurrentUserWhenUserIsNotAuthenticated() throws Exception {
        mockMvc.perform(get("/me"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithAnonymousUser
    void shouldSignUpUser() throws Exception {
        var request = new JwtRequest();
        request.setPassword("Strongpassword123@");
        request.setEmail("test@example.com");
        var response = new JwtResponse("token", "refreshToken");

        given(authService.signUp(any(JwtRequest.class))).willReturn(response);

        mockMvc.perform(post("/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(response)));
    }

    @Test
    @WithAnonymousUser
    void shouldSignInUser() throws Exception {
        var request = new JwtRequest();
        request.setPassword("Strongpassword123@");
        request.setEmail("test@example.com");
        var response = new JwtResponse("token", "refreshToken");

        given(authService.authenticate(any(JwtRequest.class))).willReturn(response);

        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(response)));
    }

    @Test
    @WithAnonymousUser
    void shouldRefreshToken() throws Exception {
        var request = new RefreshJwtRequest();
        request.setRefreshToken("refreshToken");
        var response = new JwtResponse("newToken", "newRefreshToken");

        given(authService.refreshToken(any(RefreshJwtRequest.class))).willReturn(response);

        mockMvc.perform(post("/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(response)));
    }
}


