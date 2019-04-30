package com.c4soft.springaddons.showcase;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import com.c4soft.springaddons.showcase.ShowcaseApplication.ShowcaseController;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(ShowcaseController.class)
public class ShowcaseControllerTests {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter;

	@MockBean
	JwtDecoder jwtDecoder;

	@Test
	public void demoSimpleTestAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/greeting").with(jwt()))
				.andExpect(content().string(is("Hello, user!")));

		mockMvc.perform(get("/restricted/greeting").with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_AUTHORIZED_PERSONEL"))))
				.andExpect(content().string(is("Welcome to restricted area.")));

		mockMvc.perform(get("/restricted/greeting").with(jwt()))
				.andExpect(status().isForbidden());

		// because /audience-restricted relies on a Collection of Strings, I will make sure to supply
		// this in the format the request expects it. I'll not rely on any custom bean I have to convert from
		// the JWTs native representation (which can either be a string or an array)

		mockMvc.perform(get("/audience-restricted").with(jwt(jwt -> jwt.claim(AUD, Arrays.asList("audience-1")))))
				.andExpect(content().string(is("audience-1")));

		mockMvc.perform(get("/audience-restricted").with(jwt(jwt -> jwt.claim(AUD, Arrays.asList("audience-2")))))
				.andExpect(status().isForbidden());
	}

	@Test
	public void demoJwtAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/jwt").with(jwt()))
			.andExpect(content().string(is("{sub=user}")));

		// because /restricted/greeting doesn't read the "scope" claim, there is
		// no reason to bother with providing it

		mockMvc.perform(get("/restricted/greeting").with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_AUTHORIZED_PERSONEL"))))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}

	// this method and the corresponding build class could be added to Jwt

	private static JwtBuilder withToken(String token) {
		return new JwtBuilder(token);
	}

	private static class JwtBuilder {
		private String token;
		private Map<String, Object> buildingClaims = new HashMap<>();
		private Map<String, Object> buildingHeaders = new HashMap<>();
		private Map<String, Object> claims;
		private Map<String, Object> headers;

		public JwtBuilder(String token) {
			this.token = token;
		}

		public JwtBuilder claim(String name, Object value) {
			this.buildingClaims.put(name, value);
			return this;
		}

		public JwtBuilder claims(Map<String, Object> claims) {
			this.claims = claims;
			return this;
		}

		public JwtBuilder header(String name, Object value) {
			this.buildingHeaders.put(name, value);
			return this;
		}

		public JwtBuilder headers(Map<String, Object> headers) {
			this.headers = headers;
			return this;
		}

		private Map<String, Object> getClaims() {
			if (this.claims == null) {
				return this.buildingClaims;
			}
			return this.claims;
		}

		private Map<String, Object> getHeaders() {
			if (this.headers == null) {
				return this.buildingHeaders;
			}
			return this.headers;
		}

		public Jwt build() {
			Instant iat = (Instant) getClaims().get(JwtClaimNames.IAT);
			Instant exp = (Instant) getClaims().get(JwtClaimNames.EXP);
			return new Jwt(this.token, iat, exp, getHeaders(), getClaims());
		}
	}

	// these methods and corresponding class would be embedded into SecurityMockMvcRequestPostProcessors

	private static JwtRequestPostProcessor jwt() {
		JwtBuilder jwtBuilder = withToken("token");
		jwtBuilder.header("alg", "none");
		jwtBuilder.claim(JwtClaimNames.SUB, "user");
		return new JwtRequestPostProcessor(jwtBuilder);
	}

	private static JwtRequestPostProcessor jwt(Consumer<JwtBuilder> jwtBuilderConsumer) {
		JwtBuilder jwtBuilder = withToken("token");
		jwtBuilder.header("alg", "none");
		jwtBuilder.claim(JwtClaimNames.SUB, "user");
		jwtBuilderConsumer.accept(jwtBuilder);
		return new JwtRequestPostProcessor(jwtBuilder);
	}

	private static class JwtRequestPostProcessor implements RequestPostProcessor {

		private Jwt jwt;
		private Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("SCOPE_USER");

		public JwtRequestPostProcessor(JwtBuilder jwt) {
			this.jwt = jwt.build();
		}

		public JwtRequestPostProcessor scopes(String... scopes) {
			//TODO: ...
			return this;
		}

		public JwtRequestPostProcessor authorities(GrantedAuthority... authorities) {
			this.authorities = Arrays.asList(authorities);
			return this;
		}

		public JwtRequestPostProcessor authorities(Collection<GrantedAuthority> authorities) {
			this.authorities = authorities;
			return this;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest mockHttpServletRequest) {
			JwtAuthenticationToken token = new JwtAuthenticationToken(this.jwt, this.authorities);
			return authentication(token).postProcessRequest(mockHttpServletRequest);
		}
	}
}
