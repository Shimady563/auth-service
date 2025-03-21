package com.shimady.auth.service;

import com.shimady.auth.exception.ResourceNotFoundException;
import com.shimady.auth.model.User;
import com.shimady.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Test
    void shouldSaveUser() {
        var user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setPassword("password");

        userService.saveUser(user);

        then(userRepository).should().save(user);
    }

    @Test
    void shouldGetUserByEmail() {
        var user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setPassword("password");

        given(userRepository.findByEmail(user.getEmail())).willReturn(Optional.of(user));

        var result = userService.getUserByEmail(user.getEmail());

        assertNotNull(result);
        assertEquals(user.getEmail(), result.getEmail());
    }

    @Test
    void shouldThrowExceptionWhenUserNotFoundByEmail() {
        var email = "notfound@example.com";
        given(userRepository.findByEmail(email)).willReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> userService.getUserByEmail(email));
    }
}

