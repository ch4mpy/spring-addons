package com.c4_soft.springaddons.samples.webmvc.jpa;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {

	Optional<User> findBySubject(String subject);
}
