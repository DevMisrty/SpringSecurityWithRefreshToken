package com.example.springsecuritypact2.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor @NoArgsConstructor
@Builder
public class SignInRequestDto {

    private String username;
    private String password;
    private Integer age;
}
