package com.shimady.auth.repository;

import com.shimady.auth.model.Role;
import com.shimady.auth.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@Testcontainers
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class UserRepositoryTest {
    @Container
    @ServiceConnection
    private static final PostgreSQLContainer<?> POSTGRES_CONTAINER =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:alpine"));

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    private final User user = new User();

    @BeforeEach
    public void setUp() {
        user.setEmail("email");
        user.setRole(Role.ROLE_USER);
        user.setPassword("pass");

        entityManager.persist(user);
        entityManager.flush();
    }

    @Test
    public void testSave() {
        var newUser = new User();
        newUser.setEmail("newEmail");
        newUser.setRole(Role.ROLE_USER);
        newUser.setPassword("newPass");

        userRepository.save(newUser);

        var foundUser = Optional.ofNullable((entityManager.find(User.class, newUser.getId())));

        assertTrue(foundUser.isPresent());
        assertEquals(newUser.getEmail(), foundUser.get().getEmail());
        assertEquals(newUser.getPassword(), foundUser.get().getPassword());
    }

    @Test
    public void testFindByEmail() {
        var foundUser = userRepository.findByEmail(user.getEmail());

        assertTrue(foundUser.isPresent());
        assertEquals(user.getEmail(), foundUser.get().getEmail());
    }
}
