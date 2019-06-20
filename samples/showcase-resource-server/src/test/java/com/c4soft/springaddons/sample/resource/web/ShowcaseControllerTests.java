package com.c4soft.springaddons.sample.resource.web;

import static com.c4soft.springaddons.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.jwtOauth2Authentication;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.c4soft.springaddons.sample.resource.config.ShowcaseResourceServerProperties;
import com.c4soft.springaddons.sample.resource.jpa.UserAuthorityRepository;
import com.c4soft.springaddons.sample.resource.web.ShowcaseController;
import com.c4soft.springaddons.security.test.context.support.WithMockJwtClaimSet;

@RunWith(SpringRunner.class)
@WebMvcTest( ShowcaseController.class )
@Import(ShowcaseResourceServerProperties.class)
@AutoConfigureRestDocs
public class ShowcaseControllerTests {

	@MockBean
	JwtDecoder jwtDecoder;

	@Autowired
	MockMvc mockMvc;

	@MockBean
	UserAuthorityRepository userAuthorityRepository;

	@Test
	@WithMockJwtClaimSet(name = "ch4mpy", authorities = "showcase:AUTHORIZED_PERSONEL")
	public void demoWithMockJwt() throws Exception {
		mockMvc.perform(get("/greeting"))
			.andExpect(content().string(is("Hello, ch4mpy!")))
			.andDo(document("greeting"));

		mockMvc.perform(get("/restricted"))
			.andExpect(content().string(is("Welcome to restricted area.")))
			.andDo(document("restricted"));

		mockMvc.perform(get("/claims"))
			.andExpect(content().string(containsString("{\"sub\":\"ch4mpy\",\"authorities\":[\"showcase:AUTHORIZED_PERSONEL\"]}")))
			.andDo(document("claims"));
	}

	@Test
	public void demoJwtAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/claims").with(jwtOauth2Authentication()))
			.andExpect(content().string(containsString("{\"sub\":\"user\",\"authorities\":[\"ROLE_USER\"]}")));

		mockMvc.perform(get("/restricted").with(jwtOauth2Authentication(claims -> claims.authorities("showcase:AUTHORIZED_PERSONEL"))))
			.andExpect(content().string(is("Welcome to restricted area.")));

		mockMvc.perform(get("/restricted").with(jwtOauth2Authentication()))
			.andExpect(status().isForbidden());
	}
}
