package com.cos.springjwt.security.config;

import com.cos.springjwt.repository.UserRepository;
import com.cos.springjwt.security.handler.Http401Handler;
import com.cos.springjwt.security.handler.Http403Handler;
import com.cos.springjwt.security.handler.AuthErrorHandler;
import com.cos.springjwt.security.jwt.CustomLogoutFilter;
import com.cos.springjwt.security.jwt.JwtFilter;
import com.cos.springjwt.security.jwt.JwtUtil;
import com.cos.springjwt.security.jwt.LoginFilter;
import com.cos.springjwt.security.repository.RefreshRepository;
import com.cos.springjwt.security.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshRepository refreshRepository;
    private final AuthService authService;
    private final AuthErrorHandler authErrorHandler;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {

        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http

                .cors(cors -> cors
                        .configurationSource(request -> {

                            CorsConfiguration config = new CorsConfiguration();

                            config.setAllowedOrigins(List.of("http://localhost:8080"));
                            config.setAllowedMethods(List.of("*"));
                            config.setAllowCredentials(true);
                            config.setAllowedHeaders(List.of("*"));
                            config.setExposedHeaders(List.of("access"));
                            config.setMaxAge(3600L);

                            return config;
                        }))

                .csrf(auth -> auth.disable())
                .formLogin(auth -> auth.disable())
                .httpBasic(auth -> auth.disable())

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/reissue").permitAll()
                        .anyRequest().authenticated())

                .addFilterBefore(new JwtFilter(jwtUtil, userRepository, authErrorHandler), LoginFilter.class)
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), objectMapper, jwtUtil, authService), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new CustomLogoutFilter(authService, authErrorHandler), LogoutFilter.class)

                .exceptionHandling(e -> {
                    e.accessDeniedHandler(new Http403Handler(objectMapper));
                    e.authenticationEntryPoint(new Http401Handler(objectMapper));
                })

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .build();
    }
}
