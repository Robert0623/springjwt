package com.cos.springjwt.security.jwt;

import com.cos.springjwt.domain.User;
import com.cos.springjwt.repository.UserRepository;
import com.cos.springjwt.security.domain.CustomUserDetails;
import com.cos.springjwt.security.handler.AuthErrorHandler;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final AuthErrorHandler authErrorHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String accessToken = request.getHeader("access");

        if (accessToken == null) {

            filterChain.doFilter(request, response);
            return; // 필수
        }

        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {

            authErrorHandler.handleError(response, "401", "access token 만료");
            return;
        } catch (JwtException e) {

            authErrorHandler.handleError(response, "401", "유효하지 않은 access token");
            return;
        }

        String category = jwtUtil.getCategory(accessToken);

        if (!"access".equals(category)) {

            authErrorHandler.handleError(response, "401", "access token 카테고리가 올바르지 않습니다.");
            return;
        }

        String username = jwtUtil.getUsername(accessToken);

        if (username == null || username.isBlank()) {

            filterChain.doFilter(request, response);

            return;
        }

        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {

            authErrorHandler.handleError(response, "401", "사용자를 찾을 수 없습니다. username=" + username);

            return;
        }

        CustomUserDetails customUserDetails = new CustomUserDetails(userOptional.get());

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                customUserDetails,
                null,
                customUserDetails.getAuthorities());

        if (SecurityContextHolder.getContext().getAuthentication() == null) {

            SecurityContextHolder.getContext().setAuthentication(authToken);
        }

        filterChain.doFilter(request, response);
    }
}