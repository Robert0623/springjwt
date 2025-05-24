package com.cos.springjwt.controller;

import com.cos.springjwt.security.domain.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MainController {

    // private final JWTUtil jwtUtil;

    @GetMapping("/")
    public String main(@AuthenticationPrincipal CustomUserDetails userDetails) {
        // jwtUtil.generateHs256SecretKey(); // key값 확인용. 1회용.

        System.out.println("userDetails = " + userDetails);

        return "Main Controller";
    }
}
