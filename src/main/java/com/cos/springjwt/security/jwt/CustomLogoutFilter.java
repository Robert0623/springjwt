package com.cos.springjwt.security.jwt;

import com.cos.springjwt.security.handler.AuthErrorHandler;
import com.cos.springjwt.security.service.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Arrays;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final AuthService authService;
    private final AuthErrorHandler authErrorHandler;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        if (!requestUri.matches("^\\/logout$")) {

            chain.doFilter(request, response);
            return;
        }

        String requestMethod = request.getMethod();
        if (!"POST".equals(requestMethod)) {

            chain.doFilter(request, response);
            return;
        }

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {

            authErrorHandler.handleError(response, "400", "cookie 없음");
            return;
        }

        String refresh = Arrays.stream(cookies)
                .filter(cookie -> "refresh".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (refresh == null) {

            authErrorHandler.handleError(response, "400", "refresh token 없음");
            return;
        }

        try {
            authService.logout(refresh);
        } catch (IllegalArgumentException e) {

            authErrorHandler.handleError(response, "400", e.getMessage());
            return;
        } catch (Exception e) {

            authErrorHandler.handleError(response, "500", "로그아웃 처리 중 오류 발생");
            return;
        }

        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }
}