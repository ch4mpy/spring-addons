package com.c4soft.springaddons.showcase;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.validation.annotation.Validated;

import com.c4soft.springaddons.security.oauth2.server.resource.authentication.IntrospectionOAuth2ClaimSetAuthenticationManager;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.JwtOAuth2ClaimSetAuthenticationManager;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.ClaimSetGrantedAuthoritiesConverter;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;
import com.c4soft.springaddons.showcase.jpa.JpaGrantedAuthoritiesConverter;
import com.c4soft.springaddons.showcase.jpa.UserAuthority;
import com.c4soft.springaddons.showcase.jpa.UserAuthorityRepository;

@SpringBootApplication()
public class ShowcaseResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(ShowcaseResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {

		private final JwtDecoder jwtDecoder;

		private final ShowcaseResourceServerProperties showcaseProperties;

		private final UserAuthorityRepository userAuthoritiesRepo;

		@Autowired
		public SecurityConfig(
				ShowcaseResourceServerProperties showcaseProperties,
				@Nullable UserAuthorityRepository userAuthoritiesRepo,
				@Nullable JwtDecoder jwtDecoder) {
			super();
			this.showcaseProperties = showcaseProperties;
			this.userAuthoritiesRepo = userAuthoritiesRepo;
			this.jwtDecoder = jwtDecoder;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("showcase:AUTHORIZED_PERSONEL")
					.anyRequest().authenticated();;
			// @formatter:on

			configure(http.oauth2ResourceServer());
		}

		private void configure(OAuth2ResourceServerConfigurer<HttpSecurity> resourceServerHttpSecurity) {
			if (showcaseProperties.isJwt()) {
				resourceServerHttpSecurity.jwt()
					.authenticationManager(authenticationManager());
			} else {
				resourceServerHttpSecurity.opaqueToken().authenticationManager(authenticationManager());
			}
		}

		@Bean
		@Override
		public AuthenticationManager authenticationManager() {
			if (showcaseProperties.isJwt()) {
				return new JwtOAuth2ClaimSetAuthenticationManager<>(
						jwtDecoder,
						WithAuthoritiesJwtClaimSet::new,
						jwtAuthoritiesConverter(),
						Set.of("showcase"));
			}
			return new IntrospectionOAuth2ClaimSetAuthenticationManager<>(
					showcaseProperties.getIntrospection().getEdpoint(),
					showcaseProperties.getIntrospection().getClientId(),
					showcaseProperties.getIntrospection().getPassword(),
					WithAuthoritiesIntrospectionClaimSet::new,
					introspectionAuthoritiesConverter(),
					Set.of("showcase"));
		}

		@Bean
		@ConditionalOnProperty(value = "showcase.jwt", havingValue = "false")
		public Converter<WithAuthoritiesIntrospectionClaimSet, Collection<GrantedAuthority>>
				introspectionAuthoritiesConverter() {
			if (showcaseProperties.isJpa()) {
				return new JpaGrantedAuthoritiesConverter<>(userAuthoritiesRepo);
			}
			return new ClaimSetGrantedAuthoritiesConverter<WithAuthoritiesIntrospectionClaimSet>();
		}

		@Bean
		@ConditionalOnProperty(value = "showcase.jwt", havingValue = "true")
		public Converter<WithAuthoritiesJwtClaimSet, Collection<GrantedAuthority>> jwtAuthoritiesConverter() {
			if (showcaseProperties.isJpa()) {
				return new JpaGrantedAuthoritiesConverter<>(userAuthoritiesRepo);
			}
			return new ClaimSetGrantedAuthoritiesConverter<WithAuthoritiesJwtClaimSet>();
		}
	}

	@Configuration
	@EntityScan(basePackageClasses = UserAuthority.class)
	@EnableJpaRepositories(basePackageClasses = UserAuthorityRepository.class)
	@EnableTransactionManagement
	@ConditionalOnProperty(value = "showcase.jpa", havingValue = "true")
	public static class PersistenceConfig {
	}

	@Component
	@ConfigurationProperties(prefix = "showcase")
	@Validated
	public static class ShowcaseResourceServerProperties implements Serializable {
		private static final long serialVersionUID = 7421881747366496846L;

		private	boolean jwt;

		private	boolean jpa;

		@Valid
		private final Introspection introspection;

		public ShowcaseResourceServerProperties() {
			super();
			introspection = new Introspection();
		}

		public boolean isJpa() {
			return jpa;
		}

		public void setJpa(boolean jpa) {
			this.jpa = jpa;
		}

		public boolean isJwt() {
			return jwt;
		}

		public void setJwt(boolean jwt) {
			this.jwt = jwt;
		}

		public Introspection getIntrospection() {
			return introspection;
		}

		public static class Introspection implements Serializable {
			private static final long serialVersionUID = 2942831628138818591L;

			@NotNull
			@Pattern(regexp = "^https://.+$")
			private String edpoint;

			@NotNull
			@Size(min = 1)
			private String clientId;

			@NotNull
			@Size(min = 1)
			private String password;


			public Introspection() {
				super();
			}

			public String getEdpoint() {
				return edpoint;
			}

			public void setEdpoint(String edpoint) {
				this.edpoint = edpoint;
			}

			public String getClientId() {
				return clientId;
			}

			public void setClientId(String clientId) {
				this.clientId = clientId;
			}

			public String getPassword() {
				return password;
			}

			public void setPassword(String password) {
				this.password = password;
			}
		}
	}
}
