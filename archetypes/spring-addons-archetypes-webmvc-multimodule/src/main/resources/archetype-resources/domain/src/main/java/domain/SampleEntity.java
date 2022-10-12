package ${package}.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "sample")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SampleEntity {
	@Id
	@GeneratedValue
	private Long id;

	@Column(nullable = false)
	private String label;
}
