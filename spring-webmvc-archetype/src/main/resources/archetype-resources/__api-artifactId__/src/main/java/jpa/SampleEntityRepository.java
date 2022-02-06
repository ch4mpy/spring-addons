package ${package}.jpa;

import org.springframework.data.jpa.repository.JpaRepository;

import ${package}.domain.SampleEntity;

public interface SampleEntityRepository extends JpaRepository<SampleEntity, Long> {
    
}
