/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.context.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.JTI;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.StringAttribute.InstantParser;
import org.springframework.security.test.context.support.StringAttribute.StringListParser;
import org.springframework.security.test.context.support.StringAttribute.UrlParser;
import org.springframework.security.test.support.Defaults;
import org.springframework.security.test.support.jwt.JwtAuthenticationTokenTestingBuilder;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
@Import(WithMockJwtSecurityContextFactoryTests.SecurityConfiguration.class)
public class WithMockJwtSecurityContextFactoryTests {

	private WithMockJwt.Factory factory;

	@Autowired
	Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

	@Before
	public void setup() {
		factory = new WithMockJwt.Factory(authoritiesConverter);
	}

	@WithMockJwt
	private static class Default {
	}

	@WithMockJwt(@StringAttribute(name = "scp", value = "message:read"))
	private static class CustomMini {
	}

	@WithMockJwt({
		@StringAttribute(name = SUB, value = "ch4mpy"),
		@StringAttribute(name = "scp", value = "message:read message:write") })
	private static class CustomFrequent {
	}

	@WithMockJwt({
		@StringAttribute(name = SUB, value = "ch4mpy"),
		@StringAttribute(name = "scp", value = "message:read message:write"),
		@StringAttribute(name = "custom-claim", value = "foo") })
	private static class CustomAdvanced {
	}

	@WithMockJwt(
			tokenValue = "truc",
			headers = { @StringAttribute(name = "a", value = "1") },
			claims = {
					@StringAttribute(name = SUB, value = "ch4mpy"),
					@StringAttribute(name = AUD, value = "test audience", parser = StringListParser.class),
					@StringAttribute(name = AUD, value = "other audience", parser = StringListParser.class),
					@StringAttribute(name = ISS, value = "https://test-issuer.org", parser = UrlParser.class),
					@StringAttribute(name = IAT, value = "2019-03-03T22:35:00.0Z", parser = InstantParser.class),
					@StringAttribute(name = JTI, value = "test ID"),
					@StringAttribute(name = "scp", value = "a b"),
					@StringAttribute(name = "custom-claim", value = "foo") })
	private static class CustomFull {
	}

	@Test
	public void defaults() {
		final WithMockJwt annotation = AnnotationUtils.findAnnotation(Default.class, WithMockJwt.class);

		final Authentication auth = factory.createSecurityContext(annotation).getAuthentication();

		assertThat(auth.getName()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(auth.getAuthorities()).isEmpty();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue()).isEqualTo(Defaults.JWT_VALUE);
		assertThat(jwt.getSubject()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(JwtAuthenticationTokenTestingBuilder.DEFAULT_HEADER_NAME))
				.isEqualTo(JwtAuthenticationTokenTestingBuilder.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void customMini() {
		final WithMockJwt annotation = AnnotationUtils.findAnnotation(CustomMini.class, WithMockJwt.class);

		final Authentication auth = factory.createSecurityContext(annotation).getAuthentication();

		assertThat(auth.getName()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("message:read"))).isTrue();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue()).isEqualTo(Defaults.JWT_VALUE);
		assertThat(jwt.getSubject()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(JwtAuthenticationTokenTestingBuilder.DEFAULT_HEADER_NAME))
				.isEqualTo(JwtAuthenticationTokenTestingBuilder.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void customFrequent() {
		final WithMockJwt annotation = AnnotationUtils.findAnnotation(CustomFrequent.class, WithMockJwt.class);

		final Authentication auth = factory.createSecurityContext(annotation).getAuthentication();

		assertThat(auth.getName()).isEqualTo("ch4mpy");
		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(
				auth.getAuthorities()
						.stream()
						.allMatch(
								a -> a.equals(new SimpleGrantedAuthority("message:read"))
										|| a.equals(new SimpleGrantedAuthority("message:write")))).isTrue();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue()).isEqualTo(Defaults.JWT_VALUE);
		assertThat(jwt.getSubject()).isEqualTo("ch4mpy");
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(JwtAuthenticationTokenTestingBuilder.DEFAULT_HEADER_NAME))
				.isEqualTo(JwtAuthenticationTokenTestingBuilder.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void customAdvanced() {
		final WithMockJwt annotation = AnnotationUtils.findAnnotation(CustomAdvanced.class, WithMockJwt.class);

		final Authentication auth = factory.createSecurityContext(annotation).getAuthentication();

		assertThat(auth.getName()).isEqualTo("ch4mpy");
		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(
				auth.getAuthorities()
						.stream()
						.allMatch(
								a -> a.equals(new SimpleGrantedAuthority("message:read"))
										|| a.equals(new SimpleGrantedAuthority("message:write")))).isTrue();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue()).isEqualTo(Defaults.JWT_VALUE);
		assertThat(jwt.getSubject()).isEqualTo("ch4mpy");
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();
		assertThat(jwt.getClaimAsString("custom-claim")).isEqualTo("foo");

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(JwtAuthenticationTokenTestingBuilder.DEFAULT_HEADER_NAME))
				.isEqualTo(JwtAuthenticationTokenTestingBuilder.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void custom() throws Exception {
		final var scopes = Set.of(new SimpleGrantedAuthority("a"), new SimpleGrantedAuthority("b"));

		final WithMockJwt annotation = AnnotationUtils.findAnnotation(CustomFull.class, WithMockJwt.class);

		final JwtAuthenticationToken auth =
				(JwtAuthenticationToken) factory.createSecurityContext(annotation).getAuthentication();
		final Jwt principal = (Jwt) auth.getPrincipal();

		assertThat(auth.getAuthorities()).hasSize(scopes.size());
		assertThat(auth.getAuthorities().containsAll(scopes))
				.isTrue();

		assertThat(auth.getCredentials()).isEqualTo(principal);

		assertThat(auth.getDetails()).isNull();

		assertThat(auth.getName()).isEqualTo("ch4mpy");

		assertThat(principal.getAudience()).hasSize(2);
		assertThat(principal.getAudience()).contains("test audience", "other audience");
		assertThat(principal.getExpiresAt()).isNull();
		assertThat(principal.getHeaders()).hasSize(1);
		assertThat(principal.getHeaders().get("a")).isEqualTo("1");
		assertThat(principal.getId()).isEqualTo("test ID");
		assertThat(principal.getIssuedAt()).isEqualTo(Instant.parse("2019-03-03T22:35:00.0Z"));
		assertThat(principal.getIssuer()).isEqualTo(new URL("https://test-issuer.org"));
		assertThat(principal.getSubject()).isEqualTo("ch4mpy");
		assertThat(principal.getNotBefore()).isNull();
		assertThat(principal.getTokenValue()).isEqualTo("truc");
		assertThat(principal.getClaims().get("custom-claim")).isEqualTo("foo");

	}

	public static final class FooParser implements AttributeValueParser<String, String> {

		@Override
		public String parse(String value) {
			return "foo";
		}

	}

	static class SecurityConfiguration {
		@Bean
		Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
			return jwt -> Stream.of(jwt.containsClaim("scp") ? jwt.getClaimAsString("scp").split(" ") : new String[] {})
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toSet());
		}
	}

}
