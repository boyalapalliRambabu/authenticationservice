package com.kr.authenticationservice.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.kr.authenticationservice.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
	Optional<RefreshToken> findByToken(String token);
}
