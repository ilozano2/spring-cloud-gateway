/*
 * Copyright 2013-2020 the original author or authors.
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

package org.springframework.cloud.gateway.filter.factory.jwt;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.RequestHeaderToRequestUriGatewayFilterFactory;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.gateway.test.BaseWebClientTests;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.context.support.ReactorContextTestExecutionListener;
import org.springframework.security.web.server.context.SecurityContextServerWebExchange;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestExecutionListener;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR;
import static org.springframework.cloud.gateway.test.TestUtils.getMap;

/**
 * @author Ignacio Lozano
 */
@SpringBootTest(webEnvironment = RANDOM_PORT)
@DirtiesContext
// TODO @ActiveProfiles(profiles = "request-header-web-filter")
@TestExecutionListeners(ReactorContextTestExecutionListener.class)
public class ClaimHeaderGatewayFilterFactoryTests extends BaseWebClientTests {

	static final String JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
	private TestExecutionListener reactorContextTestExecutionListener =
			new ReactorContextTestExecutionListener();

	@Bean
	SessionsInvalidationFilter filter() {
		return new SessionsInvalidationFilter();
	}

	@BeforeEach
	public void setUp() throws Exception {
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(mock(OAuth2User.class),
				Collections.emptyList(), "myId");
		SecurityContextImpl securityContext = new SecurityContextImpl(authenticationToken);

		TestSecurityContextHolder.setAuthentication(authenticationToken);
		ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext));
		TestSecurityContextHolder.setContext(securityContext);
		reactorContextTestExecutionListener.beforeTestMethod(null);
	}

	@AfterEach
	public void cleanUp() throws Exception {
		reactorContextTestExecutionListener.afterTestMethod(null);
	}
	@Test
	public void filterChangeRequestUri() {
		ClaimHeaderGatewayFilterFactory factory = new ClaimHeaderGatewayFilterFactory();
		GatewayFilter filter = factory.apply(c -> {
			c.setClaim("name");
			c.setHeaderName("X-My-Header");
		});
		MockServerHttpRequest request = MockServerHttpRequest.get("http://localhost").build();
		ServerWebExchange exchange = MockServerWebExchange.from(request);

		GatewayFilterChain filterChain = mock(GatewayFilterChain.class);
		ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);

		filter.filter(exchange, filterChain);

		System.out.println(exchange.getRequest().getHeaders());
	}

	@Test
	public void toStringFormat() {
		ClaimHeaderGatewayFilterFactory.Config config = new ClaimHeaderGatewayFilterFactory.Config();
		config.setClaim("My-Claim");
		config.setHeaderName("X-Header");
		GatewayFilter filter = new ClaimHeaderGatewayFilterFactory().apply(config);
		assertThat(filter.toString()).startsWith("[ClaimHeader").contains("claim = 'My-Claim'")
				.contains("headerName = 'X-Header'").endsWith("]");
	}

	@EnableAutoConfiguration
	@SpringBootConfiguration
	@Import(DefaultTestConfig.class)
	public static class TestConfig {

		@Value("${test.uri}")
		String uri;

		@Bean
		public RouteLocator testRouteLocator(RouteLocatorBuilder builder) {
			return builder.routes().route("claim_header_without_sso_test",
								  r -> r.path("/headers").uri(uri))
						  .build();
		}

	}

}
