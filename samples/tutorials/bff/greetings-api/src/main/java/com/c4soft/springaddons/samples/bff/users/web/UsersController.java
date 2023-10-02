package com.c4soft.springaddons.samples.bff.users.web;

import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;

import io.micrometer.observation.annotation.Observed;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

@RestController
@Tag(name = "Users")
@Observed(name = "UsersController")
public class UsersController {

	@GetMapping(path = "/users/me", produces = MediaType.APPLICATION_JSON_VALUE)
	@Tag(name = "getMe")
	public UserInfo getMe(Authentication auth) {
		if (auth instanceof JwtAuthenticationToken jwt) {
			final var claims = new OpenidClaimSet(jwt.getTokenAttributes());
			return new UserInfo(
					auth.getName(),
					claims.getIssuer().toString(),
					auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(),
					claims.getExpiresAt().toEpochMilli() / 1000,
					claims.getEmail());
		}
		return UserInfo.ANONYMOUS;
	}

	/**
	 * @param  name  user name
	 * @param  roles user roles
	 * @param  exp   expierztion time (in seconds since epoch)
	 * @author       Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	static record UserInfo(@NotNull String name, @NotNull String iss, @NotNull List<String> roles, @NotNull @Min(0L) Long exp, @NotNull String email) {
		static final UserInfo ANONYMOUS = new UserInfo("", "", List.of(), Long.MAX_VALUE, "");
	}
}
