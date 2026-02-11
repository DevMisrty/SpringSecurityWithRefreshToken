package com.example.springsecuritypact2.controller;

import com.example.springsecuritypact2.dto.*;
import com.example.springsecuritypact2.model.AuthType;
import com.example.springsecuritypact2.model.Users;
import com.example.springsecuritypact2.repository.UsersRepo;
import com.example.springsecuritypact2.service.AuthService;
import com.example.springsecuritypact2.utility.JwtService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@AllArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtUtility;
    private final UsersRepo usersRepo;
    private final AuthService authService;

    @PostMapping("/signin")
    public SignInResponseDto getUserSignIn(@RequestBody SignInRequestDto signInRequestDto) {
        return authService.signUp(signInRequestDto, AuthType.LOCAL, null);
    }

    @PostMapping("/loginpage")
    public LoginResponseDto login(@RequestBody LoginRequestDto loginRequestDto) {
        Users users = usersRepo.findByUsername(loginRequestDto.getUsername()).orElseThrow();
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequestDto.getUsername(),
                        loginRequestDto.getPassword()
                )
        );
        String accessToken = jwtUtility.generateAccessToken(users);
        String refreshToken = jwtUtility.generateRefreshToken(users);
        return new LoginResponseDto(accessToken, refreshToken);
    }

    @PostMapping("/refresh")
    public RefreshTokenRequestDto refreshToken(@RequestBody RefreshTokenRequestDto refreshTokenRequestDto) {
        log.info("Before getting token ");
        String token = refreshTokenRequestDto.getRefreshToken();
        String username = jwtUtility.extractUsername(token);
        log.info("fetch username from the token");
        Users users = usersRepo.findByUsername(username).orElseThrow();
        log.info("Fetched the users based on the username present in the Token");
        return new RefreshTokenRequestDto(jwtUtility.generateAccessToken(users));
    }
}
