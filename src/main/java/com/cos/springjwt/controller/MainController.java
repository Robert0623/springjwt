package com.cos.springjwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MainController {

    // private final JWTUtil jwtUtil;

    @GetMapping("/")
    public String main() {
        // jwtUtil.generateHs256SecretKey(); // key값 확인용. 1회용.

        return "Main Controller";
    }
}
