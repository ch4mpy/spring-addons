package ${package}.web.dtos;

import java.io.Serializable;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SampleResponseDto implements Serializable {
	private static final long serialVersionUID = -1107179772146345245L;
	
	@NotNull
	private Long id;

	@NotNull
	@NotEmpty
	private String mappedLabel;
}