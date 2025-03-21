package com.shimady.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shimady.auth.filter.JwtFilter;
import com.shimady.auth.repository.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@TestConfiguration
public class TestSecurityConfig {
    @Value("${auth.whitelist}")
    private String[] whitelist;

    @Value("${jwt.token.access.secret}")
    private String accessSecret;

    @Value("${jwt.token.refresh.secret}")
    private String refreshSecret;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
                    auth.requestMatchers(whitelist).permitAll();
                    auth.anyRequest().authenticated();
                })
                .addFilterAt(jwtFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    @Primary
    public JwtFilter jwtFilter() {
        return new TestJwtFilter(whitelist, jwtProvider(), new ObjectMapper());
    }

    @Bean
    public JwtProvider jwtProvider() {
        return new JwtProvider(accessSecret, refreshSecret);
    }


    // overriding the jwt filter to turn it off
    // because every other method didn't work
    private static class TestJwtFilter extends JwtFilter {
        public TestJwtFilter(String[] whitelist, JwtProvider jwtProvider, ObjectMapper objectMapper) {
            super(whitelist, jwtProvider, objectMapper);
        }

        @Override
        protected boolean shouldNotFilter(@NotNull HttpServletRequest request) {
            return true;
        }
    }
}