package com.c4soft.springaddons.showcase;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.support.JwtAuthenticationTokenBuilder;
import org.springframework.security.test.support.SimpleTestingAuthenticationTokenBuilder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.c4soft.springaddons.showcase.ShowcaseApplication.ShowcaseController;

@RunWith(SpringRunner.class)
@WebMvcTest(ShowcaseController.class)
public class ShowcaseControllerTests {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter;

	@MockBean
	JwtDecoder jwtDecoder;

	@Test
	public void demoSimpleTestAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/greeting").with(authentication()))
				.andExpect(content().string(is("Hello, user!")));

		mockMvc.perform(get("/restricted/greeting").with(authentication(new SimpleTestingAuthenticationTokenBuilder().authority("SCOPE_AUTHORIZED_PERSONEL"))))
				.andExpect(content().string(is("Welcome to restricted area.")));

		mockMvc.perform(get("/restricted/greeting").with(authentication()))
				.andExpect(status().isForbidden());
	}

	@Test
	public void demoJwtAuthenticationBuilder() throws Exception {
		mockMvc.perform(get("/jwt").with(jwt(grantedAuthoritiesConverter)))
			.andExpect(content().string(is("{sub=user}")));

		mockMvc.perform(get("/restricted/greeting").with(jwt(new JwtAuthenticationTokenBuilder(grantedAuthoritiesConverter).attribute("scope", "AUTHORIZED_PERSONEL"))))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}

}
