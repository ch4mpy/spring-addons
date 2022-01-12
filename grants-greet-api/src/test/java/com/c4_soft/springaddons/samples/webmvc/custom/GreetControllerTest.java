package com.c4_soft.springaddons.samples.webmvc.custom;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.samples.webmvc.custom.WithCustomAuth.Grant;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {
		GreetController.class,
		GrantsGreetApi.WebSecurityConfig.class,
		GrantsGreetApi.ServletSecurityBeansOverrides.class,
		SpringAddonsSecurityProperties.class })
@WebMvcTest(GreetController.class)
public class GreetControllerTest {

	@MockBean
	JwtDecoder jwtDecoder;

	@Autowired
	MockMvc mockMvc;

	@Test
	@WithCustomAuth(grants = { @Grant(proxiedSubject = "1111", value = { "1", "2", "3", "4" }), @Grant(proxiedSubject = "1112", value = { "1", "3" }) })
	public void test() throws Exception {
		mockMvc
				.perform(get("/greet").param("proxiedUserSubject", "1111").secure(true))
				.andExpect(status().isOk())
				.andExpect(content().string("Hello user, here are the IDs of the grants you were given by user with subject 1111: [1, 2, 3, 4]"));

		mockMvc
				.perform(get("/greet").param("proxiedUserSubject", "1112").secure(true))
				.andExpect(status().isOk())
				.andExpect(content().string("Hello user, here are the IDs of the grants you were given by user with subject 1112: [1, 3]"));
	}

}
