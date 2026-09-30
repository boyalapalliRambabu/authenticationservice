package com.kr.authenticationservice.security;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	private final SecretKey signingKey;
	private final long accessTokenExpirationMs;

	public JwtService(@Value("${app.jwt.secret}") String secretHex,
			@Value("${app.jwt.access-token-expiration-ms}") long accessTokenExpirationMs) {
		// Secret is provided as hex in config so it can be a strong random
		// value from an env var / secrets manager, not a readable passphrase.
		this.signingKey = Keys.hmacShaKeyFor(hexToBytes(secretHex));
		this.accessTokenExpirationMs = accessTokenExpirationMs;
	}

	private static byte[] hexToBytes(String hex) {
		int len = hex.length();
		byte[] out = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		}
		return out;
	}

	public String generateAccessToken(UserDetails user) {

		Date now = new Date();

		Date expiry = new Date(now.getTime() + accessTokenExpirationMs);

		String role = user.getAuthorities().stream().map(Object::toString).reduce((a, b) -> a + "," + b).orElse("");

		return Jwts.builder().subject(user.getUsername()).claim("roles", role).issuedAt(now).expiration(expiry)
				.signWith(signingKey).compact();
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public <T> T extractClaim(String token, Function<Claims, T> resolver) {
		Claims claims = Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token).getPayload();
		return resolver.apply(claims);
	}

	public boolean isTokenValid(String token, UserDetails user) {
		try {
			String username = extractUsername(token);
			Date expiration = extractClaim(token, Claims::getExpiration);
			return username.equals(user.getUsername()) && expiration.after(new Date());
		} catch (ExpiredJwtException | MalformedJwtException | SignatureException e) {
			return false;
		}
	}

}
