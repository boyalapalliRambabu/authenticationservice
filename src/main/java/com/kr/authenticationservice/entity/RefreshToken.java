package com.kr.authenticationservice.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Refresh tokens are persisted so they can be revoked (logout, password change,
 * compromise) — a stateless JWT alone cannot be invalidated early.
 */
@Entity
@Table(name = "refresh_token")
public class RefreshToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 512)
	private String token;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id", nullable = false)
	private User user;

	@Column(nullable = false)
	private Instant expiresAt;

	@Column(nullable = false)
	private boolean revoked = false;

	protected RefreshToken() {
	}

	public RefreshToken(String token, User user, Instant expiresAt) {
		this.token = token;
		this.user = user;
		this.expiresAt = expiresAt;
	}

	public Long getId() {
		return id;
	}

	public String getToken() {
		return token;
	}

	public User getUser() {
		return user;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}

	public boolean isRevoked() {
		return revoked;
	}

	public void revoke() {
		this.revoked = true;
	}

	public boolean isValid() {
		return !revoked && Instant.now().isBefore(expiresAt);
	}
}
