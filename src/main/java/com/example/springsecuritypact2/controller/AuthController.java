package com.example.springsecuritypact2.controller;

import com.example.springsecuritypact2.dto.LoginRequestDto;
import com.example.springsecuritypact2.dto.LoginResponseDto;
import com.example.springsecuritypact2.dto.RefreshTokenRequestDto;
import com.example.springsecuritypact2.dto.SignInRequestDto;
import com.example.springsecuritypact2.model.Users;
import com.example.springsecuritypact2.repository.UsersRepo;
import com.example.springsecuritypact2.utility.JwtUtility;
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
    private final PasswordEncoder passwordEncoder;
    private final JwtUtility jwtUtility;
    private final UsersRepo usersRepo;
    private final ModelMapper modelMapper;

    @PostMapping("/signin")
    public SignInRequestDto getUserSignIn(@RequestBody SignInRequestDto signInRequestDto) {
        Users users = modelMapper.map(signInRequestDto, Users.class);
        users.setRole("user");
        users.setPassword(passwordEncoder.encode(users.getPassword()));
        Users savedUser = usersRepo.save(users);
        return modelMapper.map(savedUser, SignInRequestDto.class);
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
        String accessToken = jwtUtility.createAccessToken(users);
        String refreshToken = jwtUtility.createRefreshToken(users);
        return new LoginResponseDto(accessToken, refreshToken);
    }

    @PostMapping("/refresh")
    public RefreshTokenRequestDto refreshToken(@RequestBody RefreshTokenRequestDto refreshTokenRequestDto) {
        log.info("Before getting token ");
        String token = refreshTokenRequestDto.getRefreshToken();
        String username = jwtUtility.getUsername(token);
        log.info("fetch username from the token");
        Users users = usersRepo.findByUsername(username).orElseThrow();
        log.info("Fetched the users based on the username present in the Token");
        return new RefreshTokenRequestDto(jwtUtility.createAccessToken(users));
    }
}
