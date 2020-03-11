/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class ModifiableClaimSet extends HashMap<String, Object> implements ClaimSet {
	private static final long serialVersionUID = -1967790894352277253L;

	/**
	 * @param properties initial values (copied so that "properties" is not altered when claim-set is modified)
	 */
	public ModifiableClaimSet(Map<String, Object> properties) {
		super(properties);
	}

	public ModifiableClaimSet() {
		super();
	}

	public ModifiableClaimSet(int initialCapacity, float loadFactor) {
		super(initialCapacity, loadFactor);
	}

	public ModifiableClaimSet(int initialCapacity) {
		super(initialCapacity);
	}

}