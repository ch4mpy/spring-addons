package com.c4soft.springaddons.showcase;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.configuration.JwtTestConfiguration;
import org.springframework.security.test.support.SimpleTestingAuthenticationTokenBuilder;
import org.springframework.security.test.support.jwt.JwtAuthenticationTokenTestingBuilder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.c4soft.springaddons.showcase.ShowcaseApplication.ShowcaseController;

@RunWith(SpringRunner.class)
@WebMvcTest(ShowcaseController.class)
@Import(JwtTestConfiguration.class)
public class ShowcaseControllerTests {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	Converter<Jwt, Collection<GrantedAuthority>> jwtAuthoritiesConverter;

	JwtAuthenticationTokenTestingBuilder auth;

	@Before
	public void setUp() {
		auth = new JwtAuthenticationTokenTestingBuilder(jwtAuthoritiesConverter);
	}

	@Test
	public void demoSimpleTestAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/greeting").with(authentication(new SimpleTestingAuthenticationTokenBuilder())))
				.andExpect(content().string(is("Hello, user!")));

		mockMvc.perform(get("/restricted/greeting").with(authentication(new SimpleTestingAuthenticationTokenBuilder().authority("SCOPE_AUTHORIZED_PERSONEL"))))
				.andExpect(content().string(is("Welcome to restricted area.")));

		mockMvc.perform(get("/restricted/greeting").with(authentication(new SimpleTestingAuthenticationTokenBuilder())))
				.andExpect(status().isForbidden());
	}

	@Test
	public void demoJwtAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/jwt").with(authentication(auth)))
			.andExpect(content().string(is("{sub=user}")));

		mockMvc.perform(get("/restricted/greeting").with(authentication(auth.token(jwt -> jwt.claim("scope", "AUTHORIZED_PERSONEL")))))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}

}
