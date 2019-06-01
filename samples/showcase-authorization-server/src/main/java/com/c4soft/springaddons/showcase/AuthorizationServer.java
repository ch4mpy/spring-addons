package com.c4soft.springaddons.showcase;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.c4soft.oauth2.rfc7519.JwtRegisteredClaimNames;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

@SpringBootApplication
public class AuthorizationServer {
	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServer.class, args);
	}

	@EnableAuthorizationServer
	@Configuration
	public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

		AuthenticationManager authenticationManager;
		KeyPair keyPair;

		public AuthorizationServerConfiguration(
				AuthenticationConfiguration authenticationConfiguration,
				KeyPair keyPair) throws Exception {

			this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
			this.keyPair = keyPair;
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients)
				throws Exception {
			// @formatter:off
			clients.inMemory()
				.withClient("embedded-authorities")
					.authorizedGrantTypes("password")
					.secret("{noop}secret")
					.scopes("showcase")
					.accessTokenValiditySeconds(3600)
					.autoApprove("showcase")
					.and()
				.withClient("jpa-authorities")
					.authorizedGrantTypes("password")
					.secret("{noop}secret")
					.scopes("none")
					.accessTokenValiditySeconds(3600)
					.and()
				.withClient("scope-authorites")
					.authorizedGrantTypes("password")
					.secret("{noop}secret")
					.scopes("authorities")
					.accessTokenValiditySeconds(3600);
			// @formatter:on
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			// @formatter:off
	        final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
	        tokenEnhancerChain.setTokenEnhancers(
	                Arrays.asList(new AuthenticationTokenEnhancer(), accessTokenConverter()));

	        endpoints.tokenStore(tokenStore())
	                .tokenEnhancer(tokenEnhancerChain)
	                .authenticationManager(authenticationManager);
			// @formatter:on
		}

		@Bean
		public TokenStore tokenStore() {
			return new JwtTokenStore(accessTokenConverter());
		}

		@Bean
		public JwtAccessTokenConverter accessTokenConverter() {
			final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
			converter.setKeyPair(this.keyPair);

			// final DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
			// converter.setAccessTokenConverter(accessTokenConverter);

			return converter;
		}
	}

	/**
	 * For configuring the end users recognized by this Authorization Server
	 */
	@Configuration
	class UserConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.mvcMatchers("/.well-known/jwks.json").permitAll()
					.anyRequest().authenticated().and()
				.httpBasic().and()
				.csrf().ignoringRequestMatchers(request -> "/introspect".equals(request.getRequestURI()));
		}

		@Bean
		@Override
		public UserDetailsService userDetailsService() {
			//@formatter:off
			return new InMemoryUserDetailsManager(
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.authorities("ROLE_USER")
						.build(),
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
						.username("admin")
						.password("password")
						.authorities("ROLE_USER", "showcase:AUTHORIZED_PERSONEL")
						.build());
			// @formatter:on
		}
	}

	/**
	 * Legacy Authorization Server (spring-security-oauth2) does not support any Token Introspection endpoint.
	 *
	 * This class adds ad-hoc support in order to better support the other samples in the repo.
	 */
	@FrameworkEndpoint
	class IntrospectEndpoint {
		TokenStore tokenStore;

		public IntrospectEndpoint(TokenStore tokenStore) {
			this.tokenStore = tokenStore;
		}

		@PostMapping("/introspect")
		@ResponseBody
		public Map<String, Object> introspect(@RequestParam("token") String token) {
			final OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(token);
			final Map<String, Object> attributes = new HashMap<>();
			if (accessToken == null || accessToken.isExpired()) {
				attributes.put("active", false);
				return attributes;
			}

			final OAuth2Authentication authentication = this.tokenStore.readAuthentication(token);

			attributes.put("active", true);
			attributes.put("exp", accessToken.getExpiration().getTime());
			attributes.put("scope", accessToken.getScope().stream().collect(Collectors.joining(" ")));
			attributes.put("sub", authentication.getName());

			return attributes;
		}
	}

	/**
	 * Legacy Authorization Server (spring-security-oauth2) does not support any <a href target="_blank"
	 * href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> endpoint.
	 *
	 * This class adds ad-hoc support in order to better support the other samples in the repo.
	 */
	@FrameworkEndpoint
	class JwkSetEndpoint {
		KeyPair keyPair;

		public JwkSetEndpoint(KeyPair keyPair) {
			this.keyPair = keyPair;
		}

		@GetMapping("/.well-known/jwks.json")
		@ResponseBody
		public Map<String, Object> getKey() {
			final RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
			final RSAKey key = new RSAKey.Builder(publicKey).build();
			return new JWKSet(key).toJSONObject();
		}
	}

	@Configuration
	class KeyConfig {
		@Bean
		KeyPair keyPair() {
			try {
				final String privateExponent =
						"3851612021791312596791631935569878540203393691253311342052463788814433805390794604753109719790052408607029530149004451377846406736413270923596916756321977922303381344613407820854322190592787335193581632323728135479679928871596911841005827348430783250026013354350760878678723915119966019947072651782000702927096735228356171563532131162414366310012554312756036441054404004920678199077822575051043273088621405687950081861819700809912238863867947415641838115425624808671834312114785499017269379478439158796130804789241476050832773822038351367878951389438751088021113551495469440016698505614123035099067172660197922333993";
				final String modulus =
						"18044398961479537755088511127417480155072543594514852056908450877656126120801808993616738273349107491806340290040410660515399239279742407357192875363433659810851147557504389760192273458065587503508596714389889971758652047927503525007076910925306186421971180013159326306810174367375596043267660331677530921991343349336096643043840224352451615452251387611820750171352353189973315443889352557807329336576421211370350554195530374360110583327093711721857129170040527236951522127488980970085401773781530555922385755722534685479501240842392531455355164896023070459024737908929308707435474197069199421373363801477026083786683";
				final String exponent = "65537";

				final RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
				final RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
				final KeyFactory factory = KeyFactory.getInstance("RSA");
				return new KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec));
			} catch (final Exception e) {
				throw new IllegalArgumentException(e);
			}
		}
	}

	private static final class AuthenticationTokenEnhancer implements TokenEnhancer {
		@Override
		public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
			final Map<String, Object> authClaims = new HashMap<>();
			authClaims.put(JwtRegisteredClaimNames.SUBJECT.value, authentication.getName());

			final var scopes = accessToken.getScope();
			if (scopes.contains("authorities")) {

				setScopeClaim(authClaims, authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority));

			} else if (!scopes.contains("none")) {
				setScopeClaim(authClaims, scopes.stream());

				final var scopedAuthorities = authentication.getAuthorities()
						.stream()
						.map(GrantedAuthority::getAuthority)
						.filter(authority -> scopes.contains(authority.split(":")[0]))
						.collect(Collectors.toSet());

				if (scopedAuthorities.size() > 0) {
					authClaims.put("authorities", scopedAuthorities);
				}
			}
			((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(authClaims);
			return accessToken;
		}

		private Map<String, Object> setScopeClaim(Map<String, Object> claimSet, Stream<String> scopes) {
			claimSet.put("scope", scopes.collect(Collectors.joining(" ")));
			return claimSet;
		}
	}
}
