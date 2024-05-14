package com.example.securityexample.global.security.jwt;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JwtTokenRepository extends JpaRepository<JwtToken,String> {

    Optional<JwtTokenDto> findByRefreshToken(String refreshToken);
}
