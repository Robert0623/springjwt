package com.cos.springjwt.security.handler;

import com.cos.springjwt.response.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthErrorHandler {

    private final ObjectMapper objectMapper;

    public void handleError(HttpServletResponse response, String code, String message) throws IOException {

        handleError(response, code, message, null);
    }

    public void handleError(HttpServletResponse response, String code, String message, Map<String, String> validation) throws IOException {

        log.error("[JWT 에러] Code: {}, Message: {}", code, message);

        ErrorResponse errorResponse = ErrorResponse.builder()
                .code(code)
                .message(message)
                .validation(validation)
                .build();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(Integer.parseInt(code));

        objectMapper.writeValue(response.getWriter(), errorResponse);
    }

    public ResponseEntity<ErrorResponse> createErrorResponse(String code, String message) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code(code)
                .message(message)
                .build();

        return ResponseEntity.status(Integer.parseInt(code)).body(errorResponse);
    }
}