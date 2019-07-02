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
package com.c4_soft.springaddons.sample.resource.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.c4_soft.springaddons.sample.resource.jpa.UserAuthority;
import com.c4_soft.springaddons.sample.resource.jpa.UserAuthorityRepository;

@Configuration
@EntityScan(basePackageClasses = UserAuthority.class)
@EnableJpaRepositories(basePackageClasses = UserAuthorityRepository.class)
@EnableTransactionManagement
@Profile("jpa")
public class PersistenceConfig {
}