package com.c4soft.springaddons.showcase;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.jwtClaimSet;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.testingToken;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.support.WithMockJwtClaimSet;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

@RunWith(SpringRunner.class)
@WebMvcTest(ShowcaseController.class)
public class ShowcaseControllerTests {

	@MockBean
	JwtDecoder jwtDecoder;

	@Autowired
	MockMvc mockMvc;

	@Test
	@WithMockJwtClaimSet(name = "ch4mpy", authorities = "AUTHORIZED_PERSONEL")
	public void demoWithMockJwt() throws Exception {
		mockMvc.perform(get("/greeting"))
			.andExpect(content().string(is("Hello, ch4mpy!")));

		mockMvc.perform(get("/restricted/greeting"))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}

	@Test
	public void demoSimpleTestAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/greeting").with(testingToken()))
				.andExpect(content().string(is("Hello, user!")));

		mockMvc.perform(get("/restricted/greeting").with(testingToken().authority("AUTHORIZED_PERSONEL")))
				.andExpect(content().string(is("Welcome to restricted area.")));

		mockMvc.perform(get("/restricted/greeting").with(testingToken()))
				.andExpect(status().isForbidden());
	}

	@Test
	public void demoJwtAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/jwt").with(jwtClaimSet()))
			.andExpect(content().string(containsString("Hello, testuserid! You are grantd with [ROLE_USER]")));

		mockMvc.perform(get("/restricted/greeting").with(jwtClaimSet(claims -> claims.authorities("AUTHORIZED_PERSONEL"))))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}

}
