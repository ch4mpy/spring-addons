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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Allows to work around some JDK limitations. For instance, {@link java.util.Collections} {@code UnmodifiableMap} can't be extended (private). With this, it is
 * possible to extend a Map delegating to an unmodifiable one.
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class DelegatingMap<K, V> implements Map<K, V> {

	private final Map<K, V> delegate;

	DelegatingMap() {
		this(new HashMap<>());
	}

	public DelegatingMap(Map<K, V> delegate) {
		super();
		this.delegate = delegate;
	}

	public Map<K, V> getDelegate() {
		return delegate;
	}

	@Override
	public int size() {
		return delegate.size();
	}

	@Override
	public boolean isEmpty() {
		return delegate.isEmpty();
	}

	@Override
	public boolean containsKey(Object key) {
		return delegate.containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		return delegate.containsValue(value);
	}

	@Override
	public V get(Object key) {
		return delegate.get(key);
	}

	@Override
	public V put(K key, V value) {
		return delegate.put(key, value);
	}

	@Override
	public V remove(Object key) {
		return delegate.remove(key);
	}

	@Override
	public void putAll(Map<? extends K, ? extends V> m) {
		delegate.putAll(m);
	}

	@Override
	public void clear() {
		delegate.clear();
	}

	@Override
	public Set<K> keySet() {
		return delegate.keySet();
	}

	@Override
	public Collection<V> values() {
		return delegate.values();
	}

	@Override
	public Set<Entry<K, V>> entrySet() {
		return delegate.entrySet();
	}

}
