package com.cos.springjwt.security.service;

import com.cos.springjwt.security.jwt.JwtUtil;
import com.cos.springjwt.security.repository.RefreshRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Transactional
    public void logout(String refresh) {

        String category = jwtUtil.getCategory(refresh);
        if (!"refresh".equals(category)) {

            throw new IllegalArgumentException("invalid token category");
        }

        boolean existsRefreshToken = refreshRepository.existsByRefresh(refresh);
        if (!existsRefreshToken) {

            throw new IllegalArgumentException("refresh token not found");
        }

        refreshRepository.deleteByRefresh(refresh);
    }
}