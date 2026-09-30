package com.kr.authenticationservice.exception;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;

/**
 * Runs when an unauthenticated request hits a protected endpoint. Without this,
 * Spring Security's default is an empty 403 body with no explanation — fine for
 * a browser login page, unwelcome for a JSON API client.
 */
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {

		response.setContentType("application/json");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

		Map<String, Object> body = Map.of("timestamp", Instant.now().toString(), "status", 401, "error", "Unauthorized",
				"message", "A valid access token is required for this endpoint", "path", request.getRequestURI());

		objectMapper.writeValue(response.getOutputStream(), body);
	}
}
