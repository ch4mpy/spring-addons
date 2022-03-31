package ${package}.jpa;

import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import ${package}.domain.SampleEntity;
import ${package}.domain.SampleEntity_;

public interface SampleEntityRepository extends JpaRepository<SampleEntity, Long>, JpaSpecificationExecutor<SampleEntity> {

	static Specification<Proxy> labelLike(String label) {
		return (root, query, cb) -> cb.like(root.get(SampleEntity_.label), String.format("%%%s%%", label));
	}
}
