package com.example.securityexample.global.security.jwt;


import com.example.securityexample.user.type.Role;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class JwtTokenDto {
    private String email;
    private String accessToken;
    private String refreshToken;
}
