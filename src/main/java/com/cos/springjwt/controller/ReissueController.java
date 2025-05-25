package com.cos.springjwt.controller;

import com.cos.springjwt.security.jwt.JwtUtil;
import com.cos.springjwt.security.repository.RefreshRepository;
import com.cos.springjwt.security.service.AuthService;
import io.jsonwebtoken.ExpiredJwtException;
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

    @PostMapping("/reissue")
    @Transactional
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies();
        String refresh = Arrays.stream(cookies)
                .filter(cookie -> "refresh".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (refresh == null) {

            return ResponseEntity.badRequest().body("refresh token null");
        }

        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            return ResponseEntity.badRequest().body("refresh token expired");
        }

        String category = jwtUtil.getCategory(refresh);

        if (!"refresh".equals(category)) {

            return ResponseEntity.badRequest().body("invalid refresh token");
        }

        boolean refreshTokenExists = refreshRepository.existsByRefresh(refresh);

        if (!refreshTokenExists) {

            return ResponseEntity.badRequest().body("invalid refresh token");
        }

        String username = jwtUtil.getUsername(refresh);
        List<String> roles = jwtUtil.getRoles(refresh);

        String newAccess = jwtUtil.createJwt("access", username, roles, 60 * 10 * 1000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, roles, 60 * 60 * 24 * 1000L);

        refreshRepository.deleteByRefresh(refresh);
        authService.addRefreshEntity(username, newRefresh, 60 * 60 * 24 * 1000L);

        response.setHeader("access", newAccess);
        response.addCookie(authService.createCookie("refresh", newRefresh));

        return ResponseEntity.ok().build();
    }
}
