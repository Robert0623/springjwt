package com.cos.springjwt.controller;

import com.cos.springjwt.security.jwt.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JwtUtil jwtUtil;

    @PostMapping("/reissue")
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

            return ResponseEntity.badRequest().body("access token expired");
        }

        String category = jwtUtil.getCategory(refresh);

        if (!"refresh".equals(category)) {

            return ResponseEntity.badRequest().body("invalid refresh token");
        }

        String username = jwtUtil.getUsername(refresh);
        List<String> roles = jwtUtil.getRoles(refresh);

        String newAccess = jwtUtil.createJwt("access", username, roles, 60 * 10 * 1000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, roles, 60 * 60 * 24 * 1000L);

        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh", newRefresh));

        return ResponseEntity.ok().build();
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60 * 60 * 24);
        cookie.setHttpOnly(true);

        return cookie;
    }
}
