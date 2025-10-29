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

import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.policy.PolicyBuilder;
import io.gravitee.apim.gateway.tests.sdk.resource.ResourceBuilder;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.plugin.policy.PolicyPlugin;
import io.gravitee.plugin.resource.ResourcePlugin;
import io.gravitee.policy.basicauth.configuration.BasicAuthenticationPolicyConfiguration;
import io.reactivex.observers.TestObserver;
import io.vertx.reactivex.core.buffer.Buffer;
import io.vertx.reactivex.ext.web.client.HttpResponse;
import io.vertx.reactivex.ext.web.client.WebClient;
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
@DeployApi(
    {
        "/apis/basic-authentication.json",
        "/apis/basic-authentication-without-provider.json",
        "/apis/basic-authentication-missing-provider.json",
    }
)
class BasicAuthenticationPolicyIntegrationTest
    extends AbstractPolicyTest<BasicAuthenticationPolicy, BasicAuthenticationPolicyConfiguration> {

    @ParameterizedTest(name = "Header value: ''{0}''")
    @DisplayName("Should fail if no proper Authorization header for Basic authentication")
    @ValueSource(strings = { "", "NOT_BASIC" })
    void shouldFailIfNoProperAuthorizationHeader(String authorizationHeader, WebClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        final TestObserver<HttpResponse<Buffer>> obs = client
            .get("/test")
            .putHeader(HttpHeaderNames.AUTHORIZATION, authorizationHeader)
            .rxSend()
            .test();

        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + BasicAuthenticationPolicy.DEFAULT_REALM_NAME + "\"");
                assertThat(response.bodyAsString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should fail if no resource provider configured")
    void shouldFailIfNoProvider(WebClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        final TestObserver<HttpResponse<Buffer>> obs = client
            .get("/test-no-provider")
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Basic user:pswrd")
            .rxSend()
            .test();

        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + BasicAuthenticationPolicy.DEFAULT_REALM_NAME + "\"");
                assertThat(response.bodyAsString()).isEqualTo("No authentication provider has been provided");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should fail if token is not base64")
    void shouldFailIfTokenNotBase64(WebClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        final TestObserver<HttpResponse<Buffer>> obs = client
            .get("/test")
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Basic user:pswrd")
            .rxSend()
            .test();

        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(500);
                assertThat(response.bodyAsString()).contains("Illegal base64 character");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should fail for unauthorized user")
    void shouldFailIfProviderDoNotMatch(WebClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        String token = Base64.getEncoder().encodeToString("invalid-user:password".getBytes(StandardCharsets.UTF_8));

        final TestObserver<HttpResponse<Buffer>> obs = client
            .get("/test")
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Basic " + token)
            .rxSend()
            .test();

        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + BasicAuthenticationPolicy.DEFAULT_REALM_NAME + "\"");
                assertThat(response.bodyAsString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @ParameterizedTest(name = "Authenticate with: ''{0}''")
    @DisplayName("Should authenticate properly")
    @ValueSource(strings = { "dummy-user", "dummy-user:password", "user:pwd" })
    void shouldAuthenticateProperly(String login, WebClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok("response from backend")));

        String token = Base64.getEncoder().encodeToString(login.getBytes(StandardCharsets.UTF_8));

        final TestObserver<HttpResponse<Buffer>> obs = client
            .get("/test")
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Basic " + token)
            .rxSend()
            .test();

        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(response.bodyAsString()).isEqualTo("response from backend");

                if (login.contains(":")) {
                    assertThat(response.headers().get("password-attribute")).isEqualTo(login.split(":")[1]);
                }

                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(1), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should fail when authentication provider is missing/not found")
    void shouldFailIfProviderMissing(WebClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        String token = Base64.getEncoder().encodeToString("dummy-user:password".getBytes(StandardCharsets.UTF_8));

        final TestObserver<HttpResponse<Buffer>> obs = client
            .get("/test-missing-provider")
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Basic " + token)
            .rxSend()
            .test();

        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + BasicAuthenticationPolicy.DEFAULT_REALM_NAME + "\"");
                assertThat(response.bodyAsString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
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
