package com.c4soft.springaddons.tutorials;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import lombok.Data;

@Data
public class Proxy implements Serializable {
	private static final long serialVersionUID = 8853377414305913148L;

	private final String proxiedUsername;
	private final String tenantUsername;
	private final Set<String> permissions;

	public Proxy(String proxiedUsername, String tenantUsername, Collection<String> permissions) {
		this.proxiedUsername = proxiedUsername;
		this.tenantUsername = tenantUsername;
		this.permissions = Collections.unmodifiableSet(new HashSet<>(permissions));
	}

	public boolean can(String permission) {
		return permissions.contains(permission);
	}
}