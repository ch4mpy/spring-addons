package ${package}.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

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
