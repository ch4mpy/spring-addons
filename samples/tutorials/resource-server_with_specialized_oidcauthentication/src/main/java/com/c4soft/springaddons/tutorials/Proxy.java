package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import lombok.Data;

@Data
public class Proxy {
	private final String proxiedSubject;
	private final String tenantSubject;
	private final Set<String> permissions;

	public Proxy(String proxiedSubject, String tenantSubject, Collection<String> permissions) {
		this.proxiedSubject = proxiedSubject;
		this.tenantSubject = tenantSubject;
		this.permissions = Collections.unmodifiableSet(new HashSet<>(permissions));
	}

	public boolean can(String permission) {
		return permissions.contains(permission);
	}
}