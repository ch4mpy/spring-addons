package com.c4soft.springaddons.samples.common;

import static com.c4soft.springaddons.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.jwtOauth2Authentication;
import static org.hamcrest.CoreMatchers.is;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.c4soft.springaddons.samples.common.jpa.UserAuthority;
import com.c4soft.springaddons.samples.common.jpa.UserAuthorityRepository;
import com.c4soft.springaddons.security.test.context.support.WithMockJwtClaimSet;
import com.c4soft.springaddons.showcase.JwtJpaAuthoritiesResourceServer;

@RunWith(SpringRunner.class)
@WebMvcTest( ShowcaseController.class )
@ContextConfiguration(classes = JwtJpaAuthoritiesResourceServer.class)
public class ShowcaseControllerTests {

	@MockBean
	JwtDecoder jwtDecoder;

	@Autowired
	MockMvc mockMvc;

	@MockBean
	UserAuthorityRepository userAuthorityRepo;

	@Before
	public void setUp() {
		when(userAuthorityRepo.findByUserSubject("user")).thenReturn(Set.of(
				new UserAuthority("user", "ROLE_USER")));
		when(userAuthorityRepo.findByUserSubject("ch4mpy")).thenReturn(Set.of(
				new UserAuthority("ch4mpy", "ROLE_USER"),
				new UserAuthority("ch4mpy", "AUTHORIZED_PERSONEL")));
	}

	@Test
	@WithMockJwtClaimSet(name = "ch4mpy", authorities = "AUTHORIZED_PERSONEL")
	public void demoWithMockJwt() throws Exception {
		mockMvc.perform(get("/greeting"))
			.andExpect(content().string(is("Hello, ch4mpy!")));

		mockMvc.perform(get("/restricted/greeting"))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}

	@Test
	public void demoJwtAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/claims").with(jwtOauth2Authentication()))
			.andExpect(content().string(is("{\"sub\":\"user\",\"authorities\":[\"ROLE_USER\"]}")));

		mockMvc.perform(get("/restricted/greeting").with(jwtOauth2Authentication(claims -> claims
				.authorities("AUTHORIZED_PERSONEL"))))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}

}
