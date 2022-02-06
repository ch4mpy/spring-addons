package ${package}.web;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Collectors;

import javax.transaction.Transactional;
import javax.validation.Valid;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ${package}.domain.SampleEntity;
import ${package}.exceptions.ResourceNotFoundException;
import ${package}.jpa.SampleEntityRepository;
import ${package}.web.dtos.SampleEditDto;
import ${package}.web.dtos.SampleResponseDto;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping(path = "${apiPath}", produces = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
@RequiredArgsConstructor
@Transactional
public class SampleController {
	private final SampleEntityRepository sampleRepo;
	private final SampleMapper sampleMapper;

	@GetMapping
	public List<SampleResponseDto> retrieveAll() {
		return sampleRepo.findAll().stream().map(sampleMapper::toDto).collect(Collectors.toList());
	}

	@PostMapping
	@Transactional
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<?> create(@Valid @RequestBody SampleEditDto dto, OidcAuthentication<OidcToken> auth) throws URISyntaxException {
		final SampleEntity tmp = new SampleEntity();
		sampleMapper.update(tmp, dto);
		final SampleEntity sample = sampleRepo.save(tmp);

		return ResponseEntity.created(new URI(String.format("/%d", sample.getId()))).build();
	}

	@GetMapping("/{id}")
	public SampleResponseDto retrieveById(@PathVariable(name = "id") long id) {
		return sampleRepo.findById(id).map(sampleMapper::toDto).orElseThrow(() -> new ResourceNotFoundException(String.format("No sample with ID %s", id)));
	}

	@PutMapping("/{id}")
	@Transactional
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<?> update(
			@PathVariable(name = "id") @Parameter(name = "id", in = ParameterIn.PATH, required = true, schema = @Schema(type = "long")) SampleEntity sample,
			@Valid @RequestBody SampleEditDto dto,
			OidcAuthentication<OidcToken> auth) {
		sampleMapper.update(sample, dto);
		sampleRepo.save(sample);

		return ResponseEntity.accepted().build();
	}

	@DeleteMapping("/{id}")
	@Transactional
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<?> delete(
			@PathVariable(name = "id") @Parameter(name = "id", in = ParameterIn.PATH, required = true, schema = @Schema(type = "long")) SampleEntity sample,
			OidcAuthentication<OidcToken> auth) {
		sampleRepo.delete(sample);

		return ResponseEntity.accepted().build();
	}
}
