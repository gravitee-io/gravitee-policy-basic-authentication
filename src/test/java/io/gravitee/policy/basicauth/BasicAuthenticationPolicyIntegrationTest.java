/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.basicauth;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.policy.PolicyBuilder;
import io.gravitee.apim.gateway.tests.sdk.resource.ResourceBuilder;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.plugin.policy.PolicyPlugin;
import io.gravitee.plugin.resource.ResourcePlugin;
import io.gravitee.policy.basicauth.configuration.BasicAuthenticationPolicyConfiguration;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava3.core.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
@GatewayTest
@DeployApi({ "/apis/basic-authentication.json", "/apis/basic-authentication-without-provider.json" })
class BasicAuthenticationPolicyIntegrationTest
    extends AbstractPolicyTest<BasicAuthenticationPolicy, BasicAuthenticationPolicyConfiguration> {

    @ParameterizedTest(name = "Header value: ''{0}''")
    @DisplayName("Should fail if no proper Authorization header for Basic authentication")
    @ValueSource(strings = { "", "NOT_BASIC" })
    void shouldFailIfNoProperAuthorizationHeader(String authorizationHeader, HttpClient httpClient) throws InterruptedException {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        httpClient
            .rxRequest(HttpMethod.GET, "/test")
            .flatMap(httpClientRequest -> httpClientRequest.putHeader(HttpHeaderNames.AUTHORIZATION, authorizationHeader).rxSend())
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(HttpStatusCode.UNAUTHORIZED_401);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + BasicAuthenticationPolicy.DEFAULT_REALM_NAME + "\"");
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should fail if no resource provider configured")
    void shouldFailIfNoProvider(HttpClient httpClient) throws InterruptedException {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        httpClient
            .rxRequest(HttpMethod.GET, "/test-no-provider")
            .flatMap(httpClientRequest -> httpClientRequest.putHeader(HttpHeaderNames.AUTHORIZATION, "Basic user:pswrd").rxSend())
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(HttpStatusCode.UNAUTHORIZED_401);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + BasicAuthenticationPolicy.DEFAULT_REALM_NAME + "\"");
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("No authentication provider has been provided");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should fail if token is not base64")
    void shouldFailIfTokenNotBase64(HttpClient httpClient) throws InterruptedException {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        httpClient
            .rxRequest(HttpMethod.GET, "/test")
            .flatMap(httpClientRequest -> httpClientRequest.putHeader(HttpHeaderNames.AUTHORIZATION, "Basic user:pswrd").rxSend())
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(HttpStatusCode.UNAUTHORIZED_401);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should fail for unauthorized user")
    void shouldFailIfProviderDoNotMatch(HttpClient httpClient) throws InterruptedException {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        String token = Base64.getEncoder().encodeToString("invalid-user:password".getBytes(StandardCharsets.UTF_8));

        httpClient
            .rxRequest(HttpMethod.GET, "/test")
            .flatMap(httpClientRequest -> httpClientRequest.putHeader(HttpHeaderNames.AUTHORIZATION, "Basic " + token).rxSend())
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(HttpStatusCode.UNAUTHORIZED_401);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + BasicAuthenticationPolicy.DEFAULT_REALM_NAME + "\"");
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @ParameterizedTest(name = "Authenticate with: ''{0}''")
    @DisplayName("Should authenticate properly")
    @ValueSource(strings = { "dummy-user", "dummy-user:password", "user:pwd" })
    void shouldAuthenticateProperly(String login, HttpClient httpClient) throws InterruptedException {
        wiremock.stubFor(get("/endpoint").willReturn(ok("response from backend")));

        String token = Base64.getEncoder().encodeToString(login.getBytes(StandardCharsets.UTF_8));

        httpClient
            .rxRequest(HttpMethod.GET, "/test")
            .flatMap(httpClientRequest -> httpClientRequest.putHeader(HttpHeaderNames.AUTHORIZATION, "Basic " + token).rxSend())
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(HttpStatusCode.OK_200);

                if (login.contains(":")) {
                    assertThat(response.headers().get("password-attribute")).isEqualTo(login.split(":")[1]);
                }

                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("response from backend");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(1), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Override
    public void configureResources(Map<String, ResourcePlugin> resources) {
        resources.put("dummy-auth-provider", ResourceBuilder.build("dummy-auth-provider", DummyAuthProvider.class));
    }

    @Override
    public void configurePolicies(Map<String, PolicyPlugin> policies) {
        policies.put("copy-password-attribute", PolicyBuilder.build("copy-password-attribute", CopyPasswordAttributePolicy.class));
    }
}
