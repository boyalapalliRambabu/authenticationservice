package com.kr.authenticationservice.service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.kr.authenticationservice.entity.RefreshToken;
import com.kr.authenticationservice.entity.User;
import com.kr.authenticationservice.exception.InvalidRefreshTokenException;
import com.kr.authenticationservice.repository.RefreshTokenRepository;

@Service
public class RefreshTokenService {
	private final RefreshTokenRepository refreshTokenRepository;
	private final long refreshTokenExpirationMs;
	private final SecureRandom secureRandom = new SecureRandom();

	public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
			@Value("${app.jwt.refresh-token-expiration-ms}") long refreshTokenExpirationMs) {
		this.refreshTokenRepository = refreshTokenRepository;
		this.refreshTokenExpirationMs = refreshTokenExpirationMs;
	}

	public RefreshToken createRefreshToken(User user) {
		byte[] randomBytes = new byte[64];
		secureRandom.nextBytes(randomBytes);

		String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

		RefreshToken refreshToken = new RefreshToken(token, user, Instant.now().plusMillis(refreshTokenExpirationMs));

		return refreshTokenRepository.save(refreshToken);
	}

	public RefreshToken verifyAndGet(String token) {

		RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
				.orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not recognized"));
		if (!refreshToken.isValid()) {
			throw new InvalidRefreshTokenException("Refresh token expired or revoked — please log in again");
		}
		return refreshToken;
	}

	/** Rotation: revoke the old token and issue a new one on every refresh. */
	public RefreshToken rotate(RefreshToken oldToken) {
		oldToken.revoke();
		refreshTokenRepository.save(oldToken);
		return createRefreshToken(oldToken.getUser());
	}
}
