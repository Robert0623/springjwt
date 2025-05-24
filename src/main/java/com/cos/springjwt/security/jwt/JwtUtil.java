package com.cos.springjwt.security.jwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;

// TODO: 예외처리
@Component
@Slf4j
public class JwtUtil {

    private final SecretKey secretKey;
    private final ObjectMapper objectMapper;

    public JwtUtil(@Value("${jwt.secret}") String secret, ObjectMapper objectMapper) {

        this.secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
        this.objectMapper = objectMapper;
    }

    // 시크릿키 발급 --> 일회용
    public void generateHs256SecretKey() {

        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String base64EncodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        log.info(">>>>>>>>>>>> 시크릿키: {}", base64EncodedKey);
    }

    public String getUsername(String token) {

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("username", String.class);
    }

    public List<String> getRoles(String token) {

        Object raw = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("roles");

        return objectMapper.convertValue(raw, new TypeReference<List<String>>() {});
    }

    public boolean isExpired(String token) {

        Date expiration = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();

        if (expiration == null) {
            return true;
        }

        return expiration.before(new Date());
    }

    public String createJwt(String username, List<String> roles, long expireMs) {

        return Jwts.builder()
                .claim("username", username)
                .claim("roles", roles)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expireMs))
                .signWith(secretKey)
                .compact();
    }
}