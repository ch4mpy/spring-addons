package com.c4_soft.springaddons.sample.resource.web;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.sample.resource.jpa.UserAuthorityRepository;
import com.c4_soft.springaddons.test.security.context.support.WithMockJwtClaimSet;
import com.c4_soft.springaddons.test.security.web.servlet.request.ServletJwtClaimSetAuthenticationUnitTestingSupport;

@RunWith(SpringRunner.class)
@WebMvcTest( ShowcaseController.class )
@AutoConfigureRestDocs
public class ShowcaseControllerTests extends ServletJwtClaimSetAuthenticationUnitTestingSupport {
	@MockBean
	UserAuthorityRepository userAuthorityRepository;

	@Test
	@WithMockJwtClaimSet(name = "ch4mpy", authorities = {"ROLE_USER", "AUTHORIZED_PERSONNEL"})
	public void demoWithMockJwt() throws Exception {
		mockMvc().get("/greeting")
			.andExpect(content().string(is("Hello, ch4mpy!")))
			.andDo(document("greeting"));

		mockMvc().get("/restricted")
			.andExpect(content().string(is("Welcome to restricted area.")))
			.andDo(document("restricted"));

		mockMvc().get("/claims")
			.andExpect(content().json("{\"sub\":\"ch4mpy\"}", false))
			.andDo(document("claims"));
	}

	@Test
	public void demoFlowApi() throws Exception {
		mockMvc().with(authentication().authorities("ROLE_USER")).get("/claims")
			.andExpect(content().string(containsString("{\"sub\":\"user\"}")));

		mockMvc().with(authentication().authorities("ROLE_USER", "AUTHORIZED_PERSONNEL")).get("/restricted")
			.andExpect(content().string(is("Welcome to restricted area.")));

		mockMvc().with(authentication()).get("/restricted")
			.andExpect(status().isForbidden());
	}
}
