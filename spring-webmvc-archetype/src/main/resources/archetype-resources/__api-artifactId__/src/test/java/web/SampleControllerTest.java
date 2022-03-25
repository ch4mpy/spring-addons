package ${package}.web;

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManagerResolver;

import ${package}.EnableSpringDataWebSupportTestConf;
import ${package}.domain.SampleEntity;
import ${package}.jpa.SampleEntityRepository;
import ${package}.web.dtos.SampleEditDto;

import com.c4_soft.springaddons.security.oauth2.config.synchronised.OidcServletApiSecurityConfig;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockOidcAuth;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebMvcTest(controllers = { SampleController.class })
@Import({ EnableSpringDataWebSupportTestConf.class, MockMvcSupport.class, OidcServletApiSecurityConfig.class })
@ComponentScan(basePackageClasses = { SampleMapper.class })
class SampleControllerTest {
	SampleEntity sampleEntity1;
	SampleEntity sampleEntity42;

	final ObjectMapper json = new ObjectMapper();

	@Autowired
	MockMvcSupport mockMvc;

	@MockBean
	SampleEntityRepository sampleEntityRepository;

	@Autowired
	SampleMapper sampleMapper;

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@BeforeEach
	public void before() {
		sampleEntity1 = new SampleEntity(1L, "Sample label 1");
		sampleEntity42 = new SampleEntity(42L, "Sample label 42");
		when(sampleEntityRepository.findById(1L)).thenReturn(Optional.of(sampleEntity1));
		when(sampleEntityRepository.findById(42L)).thenReturn(Optional.of(sampleEntity42));
		when(sampleEntityRepository.findAll()).thenReturn(Arrays.asList(sampleEntity1, sampleEntity42));
	}

	@Test
	void whenRetrieveAllThenOk() throws Exception {
		mockMvc.perform(get("/${api-path}").secure(true)).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(2)));
	}

	@Test
	@WithMockOidcAuth()
	void whenPostValidSampleEditDtoThenAccepted() throws Exception {
		when(sampleEntityRepository.save(any())).thenReturn(sampleEntity42);

		mockMvc.post(new SampleEditDto("Edited label"), "/${api-path}").andExpect(status().isCreated());
	}

	@Test
	@WithMockOidcAuth()
	void whenPutValidSampleEditDtoAtValidIdThenAccepted() throws Exception {
		when(sampleEntityRepository.save(any())).thenReturn(sampleEntity42);

		mockMvc.put(new SampleEditDto("Edited label"), "/${api-path}/{id}", sampleEntity42.getId()).andExpect(status().isAccepted());
	}

}
