/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.c4_soft.springaddons.sample.resource.config;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.c4_soft.oauth2.rfc7519.JwtClaimSet;
import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4_soft.springaddons.sample.resource.jpa.JpaGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.sample.resource.jpa.UserAuthorityRepository;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesClaimSet;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;

/**
 *
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Configuration
public class AuthoritiesConverterConfig {

	private static final String EMBEDDED_AUTHORITIES_CLAIM_NAME = "authorities";

	/*
	 * introspection, embedded authorities
	 */
	@Bean("claimsExtractor")
	@Profile("!jpa & !jwt")
	public Converter<Map<String, Object>, WithAuthoritiesIntrospectionClaimSet>
			embeddedAuthoritiesIntrospectionClaimsExtractor() {
		return new EmbeddedAuthoritiesIntrospectionClaimsExtractor();
	}

	@Bean("authoritiesConverter")
	@Profile("!jpa & !jwt")
	public Converter<Map<String, Object>, Set<GrantedAuthority>> embeddedIntrospectionAuthoritiesConverter(
			Converter<Map<String, Object>, WithAuthoritiesIntrospectionClaimSet> claimsExtractor) {
		return new EmbeddedGrantedAuthoritiesConverter<>(claimsExtractor);
	}

	/*
	 * JWT, embedded authorities
	 */
	@Bean("claimsExtractor")
	@Profile("!jpa & jwt")
	public Converter<Map<String, Object>, WithAuthoritiesJwtClaimSet> embeddedAuthoritiesJwtClaimsExtractor() {
		return new EmbeddedAuthoritiesJwtClaimsExtractor();
	}

	@Bean("authoritiesConverter")
	@Profile("!jpa & jwt")
	public Converter<Map<String, Object>, Set<GrantedAuthority>> embeddedJwtAuthoritiesConverter(
			Converter<Map<String, Object>, WithAuthoritiesJwtClaimSet> claimsExtractor) {
		return new EmbeddedGrantedAuthoritiesConverter<>(claimsExtractor);
	}

	/*
	 * introspection, JPA stored authorities
	 */
	@Bean("claimsExtractor")
	@Profile("jpa & !jwt")
	public Converter<Map<String, Object>, IntrospectionClaimSet> introspectionClaimsExtractor() {
		return new IntrospectionClaimsExtractor();
	}

	@Bean("authoritiesConverter")
	@Profile("jpa & !jwt")
	public Converter<Map<String, Object>, Set<GrantedAuthority>> jpaIntrospectionAuthoritiesConverter(
			UserAuthorityRepository userAuthoritiesRepo,
			Converter<Map<String, Object>, IntrospectionClaimSet> claimsExtractor) {
		return new JpaGrantedAuthoritiesConverter<>(userAuthoritiesRepo, claimsExtractor);
	}

	/*
	 * JWT, JPA stored authorities
	 */
	@Bean("claimsExtractor")
	@Profile("jpa & jwt")
	public Converter<Map<String, Object>, JwtClaimSet> jwtClaimsExtractor() {
		return new JwtClaimsExtractor();
	}

	@Bean("authoritiesConverter")
	@Profile("jpa & jwt")
	public Converter<Map<String, Object>, Set<GrantedAuthority>> jpaJwtAuthoritiesConverter(
			UserAuthorityRepository userAuthoritiesRepo,
			Converter<Map<String, Object>, JwtClaimSet> claimsExtractor) {
		return new JpaGrantedAuthoritiesConverter<>(userAuthoritiesRepo, claimsExtractor);
	}

	private static class IntrospectionClaimsExtractor implements Converter<Map<String, Object>, IntrospectionClaimSet> {
		@Override
		public IntrospectionClaimSet convert(Map<String, Object> source) {
			return new IntrospectionClaimSet(source);
		}
	}

	private static class EmbeddedAuthoritiesIntrospectionClaimsExtractor
			implements
			Converter<Map<String, Object>, WithAuthoritiesIntrospectionClaimSet> {
		@Override
		public WithAuthoritiesIntrospectionClaimSet convert(Map<String, Object> source) {
			return new WithAuthoritiesIntrospectionClaimSet(source, EMBEDDED_AUTHORITIES_CLAIM_NAME);
		}
	}

	private static class JwtClaimsExtractor implements Converter<Map<String, Object>, JwtClaimSet> {
		@Override
		public JwtClaimSet convert(Map<String, Object> source) {
			return new JwtClaimSet(source);
		}
	}

	private static class EmbeddedAuthoritiesJwtClaimsExtractor
			implements
			Converter<Map<String, Object>, WithAuthoritiesJwtClaimSet> {
		@Override
		public WithAuthoritiesJwtClaimSet convert(Map<String, Object> source) {
			return new WithAuthoritiesJwtClaimSet(source, EMBEDDED_AUTHORITIES_CLAIM_NAME);
		}
	}

	private static class EmbeddedGrantedAuthoritiesConverter<T extends WithAuthoritiesClaimSet>
			implements
			Converter<Map<String, Object>, Set<GrantedAuthority>> {
		private final Converter<Map<String, Object>, T> claimsExtractor;

		public EmbeddedGrantedAuthoritiesConverter(Converter<Map<String, Object>, T> claimsExtractor) {
			this.claimsExtractor = claimsExtractor;
		}

		@Override
		public Set<GrantedAuthority> convert(Map<String, Object> source) {
			final var authorities = claimsExtractor.convert(source).getAsStringSet(EMBEDDED_AUTHORITIES_CLAIM_NAME);
			final Stream<String> authoritiesStream = authorities == null ? Stream.empty() : authorities.stream();
			return authoritiesStream.filter(authority -> authority.contains("showcase:"))
					.map(authority -> authority.substring(9))
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toSet());
		}

	}

}
