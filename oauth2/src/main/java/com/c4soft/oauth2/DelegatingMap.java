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
package com.c4soft.oauth2;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Allows to work around some JDK limitations.
 * For instance, {@link java.util.Collections#UnmodifiableMap} can't be extended (private).
 * With this, it is possible to extend a Map delegating to an unmodifiable one.
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class DelegatingMap<T, U> implements Map<T, U> {

	private final Map<T, U> delegate;

	public DelegatingMap(Map<T, U> delegate) {
		super();
		this.delegate = delegate;
	}

	public Map<T, U> getDelegate() {
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
	public U get(Object key) {
		return delegate.get(key);
	}

	@Override
	public U put(T key, U value) {
		return delegate.put(key, value);
	}

	@Override
	public U remove(Object key) {
		return delegate.remove(key);
	}

	@Override
	public void putAll(Map<? extends T, ? extends U> m) {
		delegate.putAll(m);
	}

	@Override
	public void clear() {
		delegate.clear();
	}

	@Override
	public Set<T> keySet() {
		return delegate.keySet();
	}

	@Override
	public Collection<U> values() {
		return delegate.values();
	}

	@Override
	public Set<Entry<T, U>> entrySet() {
		return delegate.entrySet();
	}

}
