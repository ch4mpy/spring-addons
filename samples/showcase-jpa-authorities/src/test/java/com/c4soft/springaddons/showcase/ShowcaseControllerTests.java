package com.c4soft.springaddons.showcase;

import static com.c4soft.springaddons.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.jwtOauth2Authentication;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.c4soft.springaddons.security.test.context.support.WithMockJwtClaimSet;

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
	public void demoJwtAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/jwt").with(jwtOauth2Authentication()))
			.andExpect(content().string(is("{sub=user}")));

		mockMvc.perform(get("/restricted/greeting").with(jwtOauth2Authentication(claims -> claims
				.authorities("AUTHORIZED_PERSONEL"))))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}

}
