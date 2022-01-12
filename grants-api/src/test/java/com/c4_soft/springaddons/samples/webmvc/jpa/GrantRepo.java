package com.c4_soft.springaddons.samples.webmvc.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GrantRepo extends JpaRepository<Grant, Long> {
}
