package com.c4_soft.springaddons.sample.resource.web;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.sample.resource.jpa.UserAuthorityRepository;
import com.c4_soft.springaddons.security.test.context.support.WithMockJwtClaimSet;
import com.c4_soft.springaddons.security.test.support.jwt.JwtClaimSetAuthenticationUnitTestsParent;

@WebMvcTest( ShowcaseController.class )
@AutoConfigureRestDocs
public class ShowcaseControllerTests extends JwtClaimSetAuthenticationUnitTestsParent {
	@Autowired
	MockMvc mockMvc;

	@MockBean
	UserAuthorityRepository userAuthorityRepository;

	@Test
	@WithMockJwtClaimSet(name = "ch4mpy", authorities = {"ROLE_USER", "AUTHORIZED_PERSONEL"})
	public void demoWithMockJwt() throws Exception {
		mockMvc.perform(get("/greeting"))
			.andExpect(content().string(is("Hello, ch4mpy!")))
			.andDo(document("greeting"));

		mockMvc.perform(get("/restricted"))
			.andExpect(content().string(is("Welcome to restricted area.")))
			.andDo(document("restricted"));

		mockMvc.perform(get("/claims"))
			.andExpect(content().json("{\"sub\":\"ch4mpy\"}", false))
			.andDo(document("claims"));
	}

	@Test
	public void demoJwtAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/claims").with(securityRequestPostProcessor().authorities("ROLE_USER")))
			.andExpect(content().string(containsString("{\"sub\":\"user\"}")));

		mockMvc.perform(get("/restricted").with(securityRequestPostProcessor().authorities("ROLE_USER", "AUTHORIZED_PERSONEL")))
			.andExpect(content().string(is("Welcome to restricted area.")));

		mockMvc.perform(get("/restricted").with(securityRequestPostProcessor()))
			.andExpect(status().isForbidden());
	}
}
