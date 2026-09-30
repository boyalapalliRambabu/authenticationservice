package com.kr.authenticationservice.service;

import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kr.authenticationservice.dto.AuthResponse;
import com.kr.authenticationservice.dto.LoginRequest;
import com.kr.authenticationservice.dto.RefreshRequest;
import com.kr.authenticationservice.dto.RegisterRequest;
import com.kr.authenticationservice.dto.UserResponse;
import com.kr.authenticationservice.entity.RefreshToken;
import com.kr.authenticationservice.entity.Role;
import com.kr.authenticationservice.entity.User;
import com.kr.authenticationservice.exception.EmailAlreadyExistsException;
import com.kr.authenticationservice.repository.UserRepository;
import com.kr.authenticationservice.security.JwtService;

@Service
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final UserDetailsService userDetailsService;
	private final JwtService jwtService;
	private final RefreshTokenService refreshTokenService;

	public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
			AuthenticationManager authenticationManager, UserDetailsService userDetailsService, JwtService jwtService,
			RefreshTokenService refreshTokenService) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.userDetailsService = userDetailsService;
		this.jwtService = jwtService;
		this.refreshTokenService = refreshTokenService;
	}

	@Transactional
	public UserResponse register(RegisterRequest request) {
		if (userRepository.existsByEmail(request.email())) {
			throw new EmailAlreadyExistsException(request.email());
		}

//		User user = new User(request.email(), passwordEncoder.encode(request.password()), // never store plain text
//				Set.of(Role.ROLE_USER));
		User user = new User(request.email(), passwordEncoder.encode(request.password()), Set.of(Role.ROLE_USER));
		userRepository.save(user);

		return new UserResponse(user.getId(), user.getEmail(), "Registration successful. Please log in.");
	}

	public AuthResponse login(LoginRequest request) {
		// Delegates to the AuthenticationManager -> DaoAuthenticationProvider,
		// which uses our UserDetailsService + PasswordEncoder. Throws
		// BadCredentialsException on failure (handled by GlobalExceptionHandler).
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.email(), request.password()));

		User user = userRepository.findByEmail(request.email())
				.orElseThrow(() -> new IllegalStateException("Authenticated user not found — data inconsistency"));

		return issueTokens(user);
	}

	@Transactional
	public AuthResponse refresh(RefreshRequest request) {
		RefreshToken oldToken = refreshTokenService.verifyAndGet(request.refreshToken());
		User user = oldToken.getUser();

		RefreshToken newRefreshToken = refreshTokenService.rotate(oldToken);

		var userDetails = userDetailsService.loadUserByUsername(user.getEmail());
		String accessToken = jwtService.generateAccessToken(userDetails);

		return new AuthResponse(accessToken, newRefreshToken.getToken());
	}

	private AuthResponse issueTokens(User user) {
		var userDetails = userDetailsService.loadUserByUsername(user.getEmail());
		String accessToken = jwtService.generateAccessToken(userDetails);
		RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
		return new AuthResponse(accessToken, refreshToken.getToken());
	}
}
