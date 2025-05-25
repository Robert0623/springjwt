package com.cos.springjwt.security.service;

import com.cos.springjwt.security.domain.Refresh;
import com.cos.springjwt.security.jwt.JwtUtil;
import com.cos.springjwt.security.repository.RefreshRepository;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Transactional
    public void logout(String refresh) {

        try {
            String category = jwtUtil.getCategory(refresh);
            if (!"refresh".equals(category)) {

                throw new IllegalArgumentException("invalid token category");
            }
        } catch (JwtException e) {

            throw new IllegalArgumentException("유효하지 않은 refresh token");
        }


        boolean existsRefreshToken = refreshRepository.existsByRefresh(refresh);
        if (!existsRefreshToken) {

            throw new IllegalArgumentException("등록되지 않은 refresh token");
        }

        refreshRepository.deleteByRefresh(refresh);
    }

    public Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60 * 60 * 24);
        // cookie.setSecure(true); // https
        // cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }

    @Transactional
    public void addRefreshEntity(String username, String refresh, Long expiredMs) {
        LocalDateTime datetime = Instant.ofEpochMilli(System.currentTimeMillis() + expiredMs)
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();

        Refresh refreshEntity = Refresh.builder()
                .username(username)
                .refresh(refresh)
                .expiration(datetime)
                .build();

        refreshRepository.save(refreshEntity);
    }
}