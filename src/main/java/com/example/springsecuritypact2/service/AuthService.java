package com.example.springsecuritypact2.service;

import com.example.springsecuritypact2.dto.LoginRequestDto;
import com.example.springsecuritypact2.dto.LoginResponseDto;
import com.example.springsecuritypact2.dto.SignInRequestDto;
import com.example.springsecuritypact2.dto.SignInResponseDto;
import com.example.springsecuritypact2.model.AuthType;
import com.example.springsecuritypact2.model.Users;
import com.example.springsecuritypact2.repository.UsersRepo;
import com.example.springsecuritypact2.utility.JwtService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthService {
    
    private final UsersRepo usersRepo;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;

    public SignInResponseDto signUp(SignInRequestDto signInRequestDto, AuthType authType, String providerId){
        Users savedUser = getUser(signInRequestDto, authType, providerId);
        return modelMapper.map(savedUser, SignInResponseDto.class);
    }

    public Users getUser(SignInRequestDto signInRequestDto, AuthType authType, String providerId){
        Users users = Users.builder()
                .username(signInRequestDto.getUsername())
                .providerId(providerId)
                .providerType(authType)
                .role("user")
                .build();

        if(AuthType.LOCAL.equals(authType)){
            users.setPassword(passwordEncoder.encode(signInRequestDto.getPassword()));
        }

        return usersRepo.save(users);
    }

}
