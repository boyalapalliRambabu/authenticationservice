package com.kr.authenticationservice.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Sample protected endpoints demonstrating role-based authorization.
 * /api/user/** requires any authenticated user (see SecurityConfig).
 * /api/admin/** additionally requires ROLE_ADMIN.
 */
@RestController
public class DemoController {

	@GetMapping("/api/user/me")
	public Map<String, Object> me(Authentication authentication) {
		return Map.of("email", authentication.getName(), "authorities", authentication.getAuthorities());
	}

	@GetMapping("/api/admin/dashboard")
	@PreAuthorize("hasRole('ADMIN')") // belt-and-braces: also enforced in SecurityConfig
	public Map<String, String> adminDashboard() {
		return Map.of("message", "Welcome, admin — this endpoint requires ROLE_ADMIN");
	}
}
