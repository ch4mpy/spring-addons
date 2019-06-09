package com.c4soft.springaddons.showcase;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetIntrospectionAuthenticationManager;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.ClaimSetGrantedAuthoritiesConverter;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;
import com.c4soft.springaddons.showcase.jpa.JpaGrantedAuthoritiesConverter;
import com.c4soft.springaddons.showcase.jpa.UserAuthority;
import com.c4soft.springaddons.showcase.jpa.UserAuthorityRepository;

@SpringBootApplication()
public class IntrospectionEmbeddedAuthoritiesResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(IntrospectionEmbeddedAuthoritiesResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@ConditionalOnProperty(value = "jwt.enabled", havingValue = "false")
	public static class AlternanteSecurityConfig extends WebSecurityConfigurerAdapter {

		@Value("${jpa.enabled}")
		private boolean jpaEnabled;

		@Autowired
		private UserAuthorityRepository userAuthoritiesRepo;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("showcase:AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.opaqueToken()
						.authenticationManager(authenticationManager());
			// @formatter:on
		}

		@Override
		public OAuth2ClaimSetIntrospectionAuthenticationManager<WithAuthoritiesIntrospectionClaimSet> authenticationManager() {
			return new OAuth2ClaimSetIntrospectionAuthenticationManager<WithAuthoritiesIntrospectionClaimSet>(
					"https://localhost:8080/introspect",
					"showcase-resource-server",
					"secret",
					WithAuthoritiesIntrospectionClaimSet::new,
					authoritiesConverter());
		}

		public Converter<WithAuthoritiesIntrospectionClaimSet, Collection<GrantedAuthority>> authoritiesConverter() {
			if(jpaEnabled) {
				return new JpaGrantedAuthoritiesConverter<>(userAuthoritiesRepo);
			}
			return new ClaimSetGrantedAuthoritiesConverter<WithAuthoritiesIntrospectionClaimSet>();
		}
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@ConditionalOnProperty("jwt.enabled")
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Value("${jpa.enabled}")
		private boolean jpaEnabled;

		@Autowired(required = false)
		private UserAuthorityRepository userAuthoritiesRepo;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("showcase:AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.jwtAuthenticationConverter(jwt -> new OAuth2ClaimSetAuthentication<>(
								new WithAuthoritiesJwtClaimSet(jwt.getClaims()),
								authoritiesConverter()));
			// @formatter:on
		}

		public Converter<WithAuthoritiesJwtClaimSet, Collection<GrantedAuthority>> authoritiesConverter() {
			if(jpaEnabled) {
				return new JpaGrantedAuthoritiesConverter<>(userAuthoritiesRepo);
			}
			return new ClaimSetGrantedAuthoritiesConverter<WithAuthoritiesJwtClaimSet>();
		}
	}

	@Configuration
	@EntityScan(basePackageClasses = UserAuthority.class)
	@EnableJpaRepositories(basePackageClasses = UserAuthorityRepository.class)
	@EnableTransactionManagement
	public static class PersistenceConfig {
	}
}
