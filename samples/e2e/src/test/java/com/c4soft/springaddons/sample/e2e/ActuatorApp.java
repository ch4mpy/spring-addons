/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.c4soft.springaddons.sample.e2e;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.util.SocketUtils;
import org.springframework.web.client.ResourceAccessException;

import com.c4soft.springaddons.sample.e2e.dto.HealthResponse;

/**
 * Helps start and stop spring-boot apps with spring-boot-starter-actuator dependency
 *
 * @author Ch4mp
 *
 * @see Builder
 */
class ActuatorApp {
	private final int port;
	private final String actuatorEndpoint;
	private final File jarFile;
	private final TestRestTemplate actuatorClient;
	private Process process;

	private ActuatorApp(File jarFile, int port, TestRestTemplate actuatorClient) {
		this.port = port;
		this.actuatorEndpoint = getBaseUri() + "actuator/";
		this.actuatorClient = actuatorClient;
		this.jarFile = jarFile;

		Assert.isTrue(jarFile.exists(), jarFile.getAbsolutePath() + " does not exist");
	}

	public void start(List<String> profiles, List<String> additionalArgs) throws InterruptedException, IOException {
		if (isUp()) {
			stop();
		}

		this.process = Runtime.getRuntime().exec(appStartCmd(jarFile, profiles, additionalArgs));

		Executors.newSingleThreadExecutor().submit(new ProcessStdOutPrinter(process));

		for (int i = 0; i < 10 && !isUp(); ++i) {
			Thread.sleep(5000);
		}
	}

	public void start(String... profiles) throws InterruptedException, IOException {
		this.start(Arrays.asList(profiles), List.of());
	}

	public void stop() throws InterruptedException {
		if (isUp()) {
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
			headers.setAccept(List.of(MediaType.APPLICATION_JSON_UTF8));

			actuatorClient.postForEntity(actuatorEndpoint + "shutdown", new HttpEntity<>(headers), Object.class);
			Thread.sleep(5000);
		}
		if (process != null) {
			process.destroy();
		}
	}

	private String[] appStartCmd(File jarFile, List<String> profiles, List<String> additionalArgs) {
		final List<String> cmd = new ArrayList<>(
				List.of(
						"java",
						"-jar",
						jarFile.getAbsolutePath(),
						"--server.port=" + port,
						"--management.endpoint.heath.enabled=true",
						"--management.endpoint.shutdown.enabled=true",
						"--management.endpoints.web.exposure.include=*",
						"--management.endpoints.web.base-path=/actuator"));
		if (profiles.size() > 0) {
			cmd.add("--spring.profiles.active=" + profiles.stream().collect(Collectors.joining(",")));
		}
		if (additionalArgs != null) {
			cmd.addAll(additionalArgs);
		}
		return cmd.toArray(new String[0]);
	}

	private boolean isUp() {
		try {
			final ResponseEntity<HealthResponse> response =
					actuatorClient.getForEntity(actuatorEndpoint + "health", HealthResponse.class);
			return response.getStatusCode().is2xxSuccessful() && response.getBody().getStatus().equals("UP");
		} catch (ResourceAccessException e) {
			return false;
		}
	}

	public static Builder builder(String moduleName, String moduleVersion) {
		return new Builder(moduleName, moduleVersion);
	}

	/**
	 * Configure and build a spring-boot app
	 *
	 * @author Ch4mp
	 *
	 */
	public static class Builder {

		private String moduleParentDirectory = "..";

		private final String moduleName;

		private final String moduleVersion;

		private int port = SocketUtils.findAvailableTcpPort(8080);

		private String actuatorClientId = "actuator";

		private String actuatorClientSecret = "secret";

		public Builder(String moduleName, String moduleVersion) {
			this.moduleName = moduleName;
			this.moduleVersion = moduleVersion;
		}

		public Builder moduleParentDirectory(String moduleParentDirectory) {
			this.moduleParentDirectory = moduleParentDirectory;
			return this;
		}

		public Builder port(int port) {
			this.port = port;
			return this;
		}

		public Builder actuatorClientId(String actuatorClientId) {
			this.actuatorClientId = actuatorClientId;
			return this;
		}

		public Builder actuatorClientSecret(String actuatorClientSecret) {
			this.actuatorClientSecret = actuatorClientSecret;
			return this;
		}

		/**
		 * Ensures the app module is found and packaged
		 * @return app ready to be started
		 * @throws IOException if module packaging throws one
		 * @throws InterruptedException if module packaging throws one
		 */
		public ActuatorApp build() throws IOException, InterruptedException {
			final File moduleDir = new File(moduleParentDirectory, moduleName);

			packageModule(moduleDir);

			final File jarFile = new File(new File(moduleDir, "target"), moduleName + "-" + moduleVersion + ".jar");

			return new ActuatorApp(jarFile, port, new TestRestTemplate(actuatorClientId, actuatorClientSecret));
		}

		private void packageModule(File moduleDir) throws IOException, InterruptedException {
			Assert.isTrue(moduleDir.exists(), "could not find module. " + moduleDir + " does not exist.");

			String[] cmd = new File(moduleDir, "pom.xml").exists() ?
					new String[] { "mvn", "-DskipTests=true", "package" } :
					new String[] { "./gradlew", "bootJar" };

			Process mvnProcess = new ProcessBuilder().directory(moduleDir).command(cmd).start();
			Executors.newSingleThreadExecutor().submit(new ProcessStdOutPrinter(mvnProcess));

			Assert.isTrue(mvnProcess.waitFor() == 0, "module packaging exited with error status.");
		}
	}

	private static class ProcessStdOutPrinter implements Runnable {
		private InputStream inputStream;

		public ProcessStdOutPrinter(Process process) {
			this.inputStream = process.getInputStream();
		}

		@Override
		public void run() {
			new BufferedReader(new InputStreamReader(inputStream)).lines().forEach(System.out::println);
		}
	}

	public String getBaseUri() {
		return "https://localhost:" + port;
	}
}