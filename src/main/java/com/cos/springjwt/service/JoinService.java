package com.cos.springjwt.service;

import com.cos.springjwt.domain.User;
import com.cos.springjwt.repository.UserRepository;
import com.cos.springjwt.request.Join;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public void joinProcess(Join request) {

        Boolean isUserPresent = userRepository.existsByUsername(request.getUsername());

        if (isUserPresent) {
            throw new IllegalArgumentException("이미 존재하는 회원입니다.");
        }

        String rawPassword = request.getPassword();
        String encryptedPassword = bCryptPasswordEncoder.encode(rawPassword);

        User user = User.builder()
                .username(request.getUsername())
                .password(encryptedPassword)
                .roles("ROLE_ADMIN")
                .build();

        userRepository.save(user);
    }
}
