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
public class SampleEditDto implements Serializable {
	private static final long serialVersionUID = 2734365053999872845L;
	
	@NotNull
	@NotEmpty
	private String mappedLabel;
}