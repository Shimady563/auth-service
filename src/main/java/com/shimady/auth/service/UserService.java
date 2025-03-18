package com.shimady.auth.service;

import com.shimady.auth.exception.ResourceNotFoundException;
import com.shimady.auth.model.User;
import com.shimady.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;

    @Transactional
    public void saveUser(User user) {
        log.info("Saving user with email: {}", user.getEmail());
        userRepository.save(user);
    }

    protected User getUserByEmail(String email) {
        log.info("Getting user by email: {}", email);
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User with email: " + email + " not found"));
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        return getUserByEmail(username);
    }
}
