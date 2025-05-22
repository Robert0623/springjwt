package com.cos.springjwt.controller;

import com.cos.springjwt.request.Join;
import com.cos.springjwt.service.JoinService;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String join(@RequestBody Join request) {

        joinService.joinProcess(request);

        return "ok";
    }
}