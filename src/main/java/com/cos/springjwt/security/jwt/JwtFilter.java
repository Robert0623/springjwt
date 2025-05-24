package com.cos.springjwt.security.jwt;

import com.cos.springjwt.domain.User;
import com.cos.springjwt.repository.UserRepository;
import com.cos.springjwt.security.domain.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");

        if (authorization == null || !authorization.startsWith("Bearer")) {

            filterChain.doFilter(request, response);

            return; // 필수
        }

        String[] jwtHeaderParts = authorization.split(" ");

        if (jwtHeaderParts.length != 2 || !"Bearer".equals(jwtHeaderParts[0])) {

            filterChain.doFilter(request, response);

            return;
        }

        String token = jwtHeaderParts[1];

        if (jwtUtil.isExpired(token)) {

            filterChain.doFilter(request, response);

            return;
        }

        String username = jwtUtil.getUsername(token);

        if (username == null || username.isBlank()) {

            filterChain.doFilter(request, response);

            return;
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("ID 또는 PASSWORD를 찾을 수 없습니다."));

        CustomUserDetails customUserDetails = new CustomUserDetails(user);

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