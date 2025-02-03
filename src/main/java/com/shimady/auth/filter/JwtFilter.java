package com.shimady.auth.filter;

import com.shimady.auth.model.JwtAuthentication;
import com.shimady.auth.repository.JwtProvider;
import com.shimady.auth.service.JwtUtils;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    @Value("${auth.whitelist}")
    private final String[] whiteList;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private final JwtProvider provider;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        log.info("Filtering request: {}", request.getRequestURI());
        String token = JwtUtils.getTokenFromHeader(request.getHeader(AUTHORIZATION_HEADER));

        if (provider.validateAccessToken(token)) {
            log.info("Jwt token validated successfully");
            Claims claims = provider.getClaimsFromToken(token);
            JwtAuthentication authentication = JwtUtils.generateAuthentication(claims);
            authentication.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        //TODO: add error response as in my previous projects

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        for (String path : whiteList) {
            AntPathRequestMatcher matcher = new AntPathRequestMatcher(path);
            if (matcher.matches(request)) {
                return true;
            }
        }
        return false;
    }
}
