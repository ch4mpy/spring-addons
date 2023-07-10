/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oidc;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class UnmodifiableClaimSet extends DelegatingMap<String, Object> implements ClaimSet {
	private static final long serialVersionUID = 5103156342740420106L;

	public UnmodifiableClaimSet(Map<String, Object> delegate) {
		super(Collections.unmodifiableMap(new HashMap<>(delegate)));
	}

	@Override
	public String toString() {
		return this.entrySet().stream().map(e -> String.format("%s => %s", e.getKey(), e.getValue())).collect(Collectors.joining(", ", "[", "]"));
	}
}
