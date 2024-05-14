package com.example.securityexample.global.security.jwt;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtToken {

    @Id
    private String email;

    @Column
    private String accessToken;

    @Column
    private String refreshToken;
}
