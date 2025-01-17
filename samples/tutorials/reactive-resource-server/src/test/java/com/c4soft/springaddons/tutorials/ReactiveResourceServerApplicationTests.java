package com.c4soft.springaddons.tutorials;

import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.JwtMutator;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.AuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4soft.springaddons.tutorials.GreetingController.MessageDto;
import reactor.core.publisher.Mono;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureWebTestClient
@TestInstance(Lifecycle.PER_CLASS) // needed only when using non-static @MethodSource
class ReactiveResourceServerApplicationTests {
	static final AnonymousAuthenticationToken ANONYMOUS =
			new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@MockitoBean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver;

	@Autowired
	WebTestClient api;

	// needed only when using @ParameterizedTests with WithJwt.AuthenticationFactory
	@Autowired
	Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> authenticationConverter;

	WithJwt.AuthenticationFactory jwtAuthFactory;

	@BeforeEach
	public void setUp() {
		jwtAuthFactory = new WithJwt.AuthenticationFactory(Optional.empty(), Optional.of(authenticationConverter));
	}

	@Test
	void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		api.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS)).get().uri("/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@WithAnonymousUser
	void givenUserIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		api.get().uri("/greet").exchange().expectStatus().isUnauthorized();
	}

	@ParameterizedTest
	@MethodSource("identityMutators")
	void givenUserIsAuthenticated_whenGreet_thenOk(JwtMutator identityMutator) throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockJwt()
				.authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR")))
			.get().uri("/greet").exchange()
			.expectStatus().isOk()
			.expectBody(MessageDto.class).isEqualTo(new MessageDto("Hi user! You are granted with: [NICE, AUTHOR]."));
		// @formatter:on
	}

	static Stream<JwtMutator> identityMutators() {
		return Stream.of(
				SecurityMockServerConfigurers.mockJwt().jwt(jwt -> jwt.subject("ch4mp"))
						.authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR")),
				SecurityMockServerConfigurers.mockJwt().jwt(jwt -> jwt.subject("tonton-pirate"))
						.authorities(new SimpleGrantedAuthority("UNCLE"), new SimpleGrantedAuthority("SKIPPER")));
	}

	@ParameterizedTest
	@AuthenticationSource({
			@WithMockAuthentication(name = "ch4mp", authorities = { "NICE", "AUTHOR" }),
			@WithMockAuthentication(name = "tonton-pirate", authorities = { "UNCLE", "SKIPPER" }) })
	void givenUserIsAuthenticatedWithMockAuthentication_whenGreet_thenOk(@ParameterizedAuthentication Authentication auth) throws Exception {
		// @formatter:off
		api.get().uri("/greet").exchange()
			.expectStatus().isOk()
			.expectBody(MessageDto.class).isEqualTo(new MessageDto("Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities())));
		// @formatter:on
	}

	@ParameterizedTest
	@MethodSource("jwts")
	void givenUserIsAuthenticatedWithJwt_whenGreet_thenOk(@ParameterizedAuthentication Authentication auth) throws Exception {
		// @formatter:off
		api.get().uri("/greet").exchange()
			.expectStatus().isOk()
			.expectBody(MessageDto.class).isEqualTo(new MessageDto("Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities())));
		// @formatter:on
	}

	Stream<AbstractAuthenticationToken> jwts() {
		return jwtAuthFactory.authenticationsFrom("auth0_badboy.json", "auth0_nice.json");
	}

	@Test
	void givenUserHasNiceMutator_whenGetRestricted_thenOk() throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockJwt()
				.authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR")))
			.get().uri("/restricted").exchange()
			.expectStatus().isOk()
			.expectBody(MessageDto.class).isEqualTo(new MessageDto("You are so nice!"));
		// @formatter:on
	}

	@Test
	@WithMockAuthentication({ "NICE", "AUTHOR" })
	void givenUserHasNiceMockAuthentication_whenGetRestricted_thenOk() throws Exception {
		// @formatter:off
		api.get().uri("/restricted").exchange()
			.expectStatus().isOk()
			.expectBody(MessageDto.class).isEqualTo(new MessageDto("You are so nice!"));
		// @formatter:on
	}

	@Test
	@WithJwt("auth0_nice.json")
	void givenUserIsNice_whenGetRestricted_thenOk() throws Exception {
		// @formatter:off
		api.get().uri("/restricted").exchange()
			.expectStatus().isOk()
			.expectBody(MessageDto.class).isEqualTo(new MessageDto("You are so nice!"));
		// @formatter:on
	}

	@Test
	void givenUserHasNotNiceMutator_whenGetRestricted_thenForbidden() throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockJwt().authorities(new SimpleGrantedAuthority("AUTHOR")))
			.get().uri("/restricted").exchange()
			.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	@WithMockAuthentication("AUTHOR")
	void givenUserHasNotNiceMockAuthentication_whenGetRestricted_thenForbidden() throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockJwt().authorities(new SimpleGrantedAuthority("AUTHOR")))
			.get().uri("/restricted").exchange()
			.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	@WithJwt("auth0_badboy.json")
	void givenUserIsBadboy_whenGetRestricted_thenForbidden() throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockJwt().authorities(new SimpleGrantedAuthority("AUTHOR")))
			.get().uri("/restricted").exchange()
			.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	void givenUserHasAnonymousMutator_whenGetRestricted_thenForbidden() throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS))
			.get().uri("/restricted").exchange()
			.expectStatus().isUnauthorized();
		// @formatter:on
	}

	@Test
	@WithAnonymousUser
	void givenUserIsAnonymous_whenGetRestricted_thenUnauthorized() throws Exception {
		api.get().uri("/restricted").exchange().expectStatus().isUnauthorized();
	}

}
