package com.c4_soft.dzone_oauth2_spring.official_greeting_api;

import java.time.Instant;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.constraints.NotNull;

@RestController
@RequestMapping("/users")
public class UsersController {
	
	@GetMapping(path = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
	@PreAuthorize("permitAll()")
	public UserDto getMe(Authentication auth) {
		if(auth instanceof JwtAuthenticationToken jwt) {
			final var username = jwt.getName();
			final var roles = jwt.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
			final var exp = (Instant) jwt.getToken().getExpiresAt();
			return new UserDto(username, roles, exp.getEpochSecond());
		}
		return UserDto.ANONYMOUS;
	}

	static record UserDto(@NotNull String username, @NotNull List<String> roles, @NotNull Long exp) {
		static final UserDto ANONYMOUS = new UserDto("", List.of(), Long.MAX_VALUE);
	}
}
