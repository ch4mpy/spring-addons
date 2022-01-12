package com.c4_soft.springaddons.samples.webmvc.web;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.samples.webmvc.jpa.Grant;
import com.c4_soft.springaddons.samples.webmvc.jpa.GrantRepo;
import com.c4_soft.springaddons.samples.webmvc.jpa.Proxy;
import com.c4_soft.springaddons.samples.webmvc.jpa.User;
import com.c4_soft.springaddons.samples.webmvc.jpa.UserRepo;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/grants")
@RequiredArgsConstructor
public class GrantsController {
	private final GrantRepo grantRepo;
	private final UserRepo userRepo;

	@PostConstruct
	public void init() {
		final Grant readA = grantRepo.save(new Grant(null, "readA"));
		final Grant writeA = grantRepo.save(new Grant(null, "writeA"));
		final Grant readB = grantRepo.save(new Grant(null, "readB"));
		grantRepo.save(new Grant(null, "writeB"));

		final User tontonpirate = userRepo.save(new User(null, "f6ab8283-6139-46d6-8b38-2484a44b7cf9", Collections.emptySet()));
		// Admin can do readA, writeA, readB (but not writeB) on behalf of Tonton Pirate
		userRepo
				.save(
						new User(
								null,
								"1e08249b-4ef8-444b-9e74-364bdae65743",
								new HashSet<>(Arrays.asList(new Proxy(null, tontonpirate, new HashSet<>(Arrays.asList(readA, writeA, readB)))))));
	}

	@GetMapping
	public ResponseEntity<Collection<Grant>> getAllGrants() {
		return ResponseEntity.ok(grantRepo.findAll());
	}

	@GetMapping("/{userSubject}")
	public ResponseEntity<UserProxiesDto> getUserProxies(@PathVariable String userSubject) {
		return ResponseEntity
				.ok(
						userRepo
								.findBySubject(userSubject)
								.map(User::getProxies)
								.map(
										proxies -> proxies
												.stream()
												.map(
														proxy -> new ProxyDto(
																proxy.getProxiedUser().getSubject(),
																proxy.getGrants().stream().map(Grant::getId).collect(Collectors.toSet())))
												.collect(Collectors.toSet()))
								.map(UserProxiesDto::new)
								.orElseThrow(() -> new RuntimeException(String.format("User not found: %s", userSubject))));
	}
}
