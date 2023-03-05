package com.c4soft.springaddons.samples.bff.users.web;

import java.io.Serializable;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@RestController
@RequestMapping(path = "/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class UsersController {

	@GetMapping("/me")
	@Operation(operationId = "UsersGetClaims", responses = { @ApiResponse(responseCode = "200"), @ApiResponse(responseCode = "401") })
	@SecurityRequirements()
	public UserDto getClaims(OAuthentication<OpenidClaimSet> auth) {
		return new UserDto(auth.getName(), auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(), auth.getPrincipal().getEmail());
	}

	@Data
	@AllArgsConstructor
	@Builder
	public static class UserDto implements Serializable {
		private static final long serialVersionUID = -5404506920234624316L;

		private String username;
		private List<String> roles;
		private String email;
	}
}
