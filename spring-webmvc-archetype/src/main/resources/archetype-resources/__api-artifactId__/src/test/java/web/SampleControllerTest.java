package ${package}.web;

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import ${package}.EnableSpringDataWebSupportTestConf;
import ${package}.domain.SampleEntity;
import ${package}.jpa.SampleEntityRepository;
import ${package}.web.dtos.SampleEditDto;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockOidcAuth;
import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import({ EnableSpringDataWebSupportTestConf.class })
class SampleControllerTest {
	SampleEntity sampleEntity1;
	SampleEntity sampleEntity42;

	final ObjectMapper json = new ObjectMapper();

	@Autowired
	MockMvc mockMvc;

	@MockBean
	SampleEntityRepository sampleEntityRepository;

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
		mockMvc.perform(get("/${api-path}")).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(2)));
	}

	@Test
	@WithMockOidcAuth()
	void whenPutValidSampleEditDtoAtValidIdThenAccepted() throws Exception {
		final SampleEditDto payload = new SampleEditDto("Edited label");
		when(sampleEntityRepository.save(any())).thenReturn(sampleEntity42);

		mockMvc
				.perform(
						put("/${api-path}/{solutionId}", sampleEntity42.getId())
								.characterEncoding("UTF-8")
								.contentType(MediaType.APPLICATION_JSON)
								.content(json.writeValueAsBytes(payload)))
				.andExpect(status().isAccepted());
	}

}
