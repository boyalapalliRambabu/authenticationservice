	package com.kr.authenticationservice.config;
	
	import java.util.List;
	
	import org.springframework.context.annotation.Bean;
	import org.springframework.context.annotation.Configuration;
	import org.springframework.security.authentication.AuthenticationManager;
	import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
	import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
	import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
	import org.springframework.security.config.annotation.web.builders.HttpSecurity;
	import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
	import org.springframework.security.config.http.SessionCreationPolicy;
	import org.springframework.security.core.userdetails.UserDetailsService;
	import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
	import org.springframework.security.crypto.password.PasswordEncoder;
	import org.springframework.security.web.SecurityFilterChain;
	import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
	import org.springframework.web.cors.CorsConfiguration;
	import org.springframework.web.cors.CorsConfigurationSource;
	import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
	
	import com.kr.authenticationservice.exception.RestAuthenticationEntryPoint;
	import com.kr.authenticationservice.security.JwtAuthenticationFilter;
	
	/**
	 * Spring Security 6.x (Spring Boot 3.x) configuration.
	 *
	 * IMPORTANT: WebSecurityConfigurerAdapter was REMOVED in Spring Security 6 — if
	 * you see tutorials extending it, they're for Spring Security 5 and will not
	 * compile against this Spring Boot version. The replacement is a
	 * SecurityFilterChain @Bean using the lambda DSL, as below.
	 */
	@Configuration
	@EnableWebSecurity
	@EnableMethodSecurity // enables @PreAuthorize on controller/service methods
	public class SecurityConfig {
	
		private final JwtAuthenticationFilter jwtAuthenticationFilter;
		private final RestAuthenticationEntryPoint authenticationEntryPoint;
	
		public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
				RestAuthenticationEntryPoint authenticationEntryPoint) {
			this.jwtAuthenticationFilter = jwtAuthenticationFilter;
			this.authenticationEntryPoint = authenticationEntryPoint;
		}
	
		@Bean
		public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			http
					// Stateless JWT API: no CSRF token needed (CSRF matters when the
					// browser automatically attaches cookies; a Bearer token in a
					// header is not automatically attached, so it isn't CSRF-exposed
					// the same way session cookies are).
					.csrf(csrf -> csrf.disable()).cors(cors -> cors.configurationSource(corsConfigurationSource()))
					.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
					.exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint))
					.authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/**").permitAll() // demo only — remove in
							.requestMatchers("/api/admin/**").hasRole("ADMIN").anyRequest().authenticated())
					// Needed only because H2 console renders in a frame; remove
					// alongside the h2-console permit above outside of local demos.
					.headers(headers -> headers.frameOptions(frame -> frame.disable()))
					.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
	
			return http.build();
		}
	
		@Bean
		public PasswordEncoder passwordEncoder() {
			// BCrypt, not NoOpPasswordEncoder — never store or compare plain-text
			// passwords, including in demo code.
			return new BCryptPasswordEncoder();
		}
	
		@Bean
		public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
			return config.getAuthenticationManager();
		}
	
		@Bean
		public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
				PasswordEncoder passwordEncoder) {
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
	//		provider.setUserDetailsService(userDetailsService);
			provider.setPasswordEncoder(passwordEncoder);
			return provider;
		}
	
	
		@Bean
		public CorsConfigurationSource corsConfigurationSource() {
			CorsConfiguration config = new CorsConfiguration();
			// Demo default — replace with your actual frontend origin(s) in production.
			config.setAllowedOrigins(List.of("http://localhost:3000"));
			config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
			config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
			config.setAllowCredentials(true);
	
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
			source.registerCorsConfiguration("/**", config);
			return source;
		}
	}
