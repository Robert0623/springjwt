package com.cos.springjwt.controller;

import com.cos.springjwt.security.handler.AuthErrorHandler;
import com.cos.springjwt.security.jwt.JwtUtil;
import com.cos.springjwt.security.repository.RefreshRepository;
import com.cos.springjwt.security.service.AuthService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;
    private final AuthService authService;
    private final AuthErrorHandler authErrorHandler;

    @PostMapping("/reissue")
    @Transactional
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {

            return authErrorHandler.createErrorResponse("400", "cookie 없음");
        }

        String refresh = Arrays.stream(cookies)
                .filter(cookie -> "refresh".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (refresh == null) {

            return authErrorHandler.createErrorResponse("400", "refresh token 없음");
        }

        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            return authErrorHandler.createErrorResponse("401", "refresh token 만료");
        } catch (JwtException e) {

            return authErrorHandler.createErrorResponse("401", "유효하지 않은 refresh token");
        }

        String category = jwtUtil.getCategory(refresh);

        if (!"refresh".equals(category)) {

            return authErrorHandler.createErrorResponse("401", "refresh token 카테고리 불일치");
        }

        boolean refreshTokenExists = refreshRepository.existsByRefresh(refresh);

        if (!refreshTokenExists) {

            return authErrorHandler.createErrorResponse("401", "등록되지 않은 refresh token");
        }

        try {
            String username = jwtUtil.getUsername(refresh);
            List<String> roles = jwtUtil.getRoles(refresh);

            String newAccess = jwtUtil.createJwt("access", username, roles, 60 * 10 * 1000L);
            String newRefresh = jwtUtil.createJwt("refresh", username, roles, 60 * 60 * 24 * 1000L);

            refreshRepository.deleteByRefresh(refresh);
            authService.addRefreshEntity(username, newRefresh, 60 * 60 * 24 * 1000L);

            response.setHeader("access", newAccess);
            response.addCookie(authService.createCookie("refresh", newRefresh));

            return ResponseEntity.ok().build();
        } catch (Exception e) {

            return authErrorHandler.createErrorResponse("500", "토큰 재발급 중 오류 발생");
        }
    }
}
