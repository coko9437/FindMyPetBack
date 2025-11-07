package com.busanit501.findmyfet.security;


import com.busanit501.findmyfet.domain.User;
import com.busanit501.findmyfet.repository.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
@RequiredArgsConstructor
@Log4j2
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JwtAuthenticationFilter: doFilterInternal called for URI: {}", request.getRequestURI());
        String token = extractToken(request);

        if (StringUtils.hasText(token)) {
            log.info("JwtAuthenticationFilter: Token found: {}", token);
            try {
                Claims claims = jwtUtil.validateToken(token);
                String loginId = claims.getSubject();
                log.info("JwtAuthenticationFilter: Token validated for loginId: {}", loginId);

                User user = userRepository.findByLoginId(loginId)
                        .orElseThrow(() -> new RuntimeException("User not found"));
                log.info("JwtAuthenticationFilter: User found: {}", user.getLoginId());

                UserDetailsImpl userDetails = new UserDetailsImpl(user); // Create UserDetailsImpl instance
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, // Principal: UserDetailsImpl 객체로 설정
                        null,
                        userDetails.getAuthorities() // UserDetailsImpl에서 권한 가져오기
                );
                log.info("JwtAuthenticationFilter: Authorities: {}", authentication.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("JwtAuthenticationFilter: SecurityContextHolder updated.");

            } catch (Exception e) {
                log.error("JwtAuthenticationFilter: Token validation failed or user not found: {}", e.getMessage());
                SecurityContextHolder.clearContext();
            }
        } else {
            log.info("JwtAuthenticationFilter: No token found in request.");
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }}

