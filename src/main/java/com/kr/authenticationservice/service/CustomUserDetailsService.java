package com.kr.authenticationservice.service;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.kr.authenticationservice.entity.User;
import com.kr.authenticationservice.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	public CustomUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("No user with email: " + email));

		System.out.println("The user is " + user);

		List<GrantedAuthority> authorities = user.getRoles().stream()
				.map(role -> new SimpleGrantedAuthority(role.name())).map(GrantedAuthority.class::cast).toList();

		return org.springframework.security.core.userdetails.User.withUsername(user.getEmail())
				.password(user.getPassword()).authorities(authorities).disabled(!user.isEnabled()).build();
	}

}
