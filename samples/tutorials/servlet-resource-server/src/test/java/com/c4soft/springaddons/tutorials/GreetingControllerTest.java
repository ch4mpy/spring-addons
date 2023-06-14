package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockBearerTokenAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOAuth2Login;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOidcLogin;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.BearerAuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.JwtAuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.OAuth2LoginAuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.OidcLoginAuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.OpenIdAuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedBearerAuth;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedOAuth2Login;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedOidcLogin;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedOpenId;

import jakarta.servlet.http.HttpServletRequest;

@WebMvcTest(controllers = GreetingController.class)
@Import({ WebSecurityConfig.class })
class GreetingControllerTest {

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Autowired
	MockMvc api;

	@Test
	void givenRequestIsNotAuthorized_whenGetGreet_thenUnauthorized() throws Exception {
		api.perform(get("/greet")).andExpect(status().isUnauthorized());
	}

	@Test
	void givenUserAuthenticated_whenGetGreet_thenOk() throws Exception {
		// @formatter:off
		api.perform(get("/greet").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR"))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("Hi user! You are granted with: [NICE, AUTHOR]."));
		// @formatter:on
	}

	@Test
	void givenRequestIsNotAuthorized_whenGetRestricted_thenUnauthorized() throws Exception {
		api.perform(get("/restricted")).andExpect(status().isUnauthorized());
	}

	@Test
	void givenUserIsNice_whenGetRestricted_thenOk() throws Exception {
		// @formatter:off
		api.perform(get("/restricted").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR"))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
	}

	@Test
	void givenUserIsNotNice_whenGetRestricted_thenForbidden() throws Exception {
		// @formatter:off
		api.perform(get("/restricted").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority("AUTHOR"))))
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@ParameterizedTest
	@ValueSource(strings = { "NICE", "VERY_NICE" })
	void givenUserIsGrantedWithAnyNiceAuthority_whenGetRestricted_thenOk(String authority) throws Exception {
		// @formatter:off
		api.perform(get("/restricted").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority(authority))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
	}

	@ParameterizedTest
	@JwtAuthenticationSource({ @WithMockJwtAuth("NICE"), @WithMockJwtAuth("VERY_NICE") })
	void givenUserIsGrantedWithAnyJwtAuthentication_whenGetRestricted_thenOk(@ParameterizedJwtAuth JwtAuthenticationToken auth) throws Exception {
		// @formatter:off
		api.perform(get("/restricted"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
	}

	@ParameterizedTest
	@BearerAuthenticationSource({ @WithMockBearerTokenAuthentication("NICE"), @WithMockBearerTokenAuthentication("VERY_NICE") })
	void givenUserIsGrantedWithAnyBearerAuthentication_whenGetRestricted_thenOk(@ParameterizedBearerAuth BearerTokenAuthentication auth) throws Exception {
		// @formatter:off
		api.perform(get("/restricted"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
	}

	@ParameterizedTest
	@OpenIdAuthenticationSource({ @OpenId("NICE"), @OpenId("VERY_NICE") })
	void givenUserIsGrantedWithAnyOAuthentication_whenGetRestricted_thenOk(@ParameterizedOpenId OAuthentication<OpenidClaimSet> auth) throws Exception {
		// @formatter:off
		api.perform(get("/restricted"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
	}

	@ParameterizedTest
	@OAuth2LoginAuthenticationSource({ @WithOAuth2Login("NICE"), @WithOAuth2Login("VERY_NICE") })
	void givenUserIsGrantedWithAnyOAuth2Login_whenGetRestricted_thenOk(@ParameterizedOAuth2Login OAuth2AuthenticationToken auth) throws Exception {
		// @formatter:off
		api.perform(get("/restricted"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
	}

	@ParameterizedTest
	@OidcLoginAuthenticationSource({ @WithOidcLogin("NICE"), @WithOidcLogin("VERY_NICE") })
	void givenUserIsGrantedWithAnyOidcLogin_whenGetRestricted_thenOk(@ParameterizedOidcLogin OAuth2AuthenticationToken auth) throws Exception {
		// @formatter:off
		api.perform(get("/restricted"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
	}
}
