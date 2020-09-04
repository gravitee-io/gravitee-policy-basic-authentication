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

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.basicauth.configuration.BasicAuthenticationPolicyConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;

import java.util.Base64;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class BasicAuthenticationPolicy {

    /**
     * Basic authentication policy configuration
     */
    private final BasicAuthenticationPolicyConfiguration basicAuthenticationPolicyConfiguration;

    private final static String BASIC_AUTHENTICATION_VALUE = "BASIC ";
    private final static String DEFAULT_REALM_NAME = "gravitee.io";

    public BasicAuthenticationPolicy(BasicAuthenticationPolicyConfiguration basicAuthenticationPolicyConfiguration) {
        this.basicAuthenticationPolicyConfiguration = basicAuthenticationPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String authorizationHeader = request.headers().getFirst(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null || authorizationHeader.trim().isEmpty()) {
            sendAuthenticationFailure(response, policyChain);
            return;
        }

        if (! authorizationHeader.toUpperCase().startsWith(BASIC_AUTHENTICATION_VALUE)) {
            sendAuthenticationFailure(response, policyChain);
            return;
        }

        if (basicAuthenticationPolicyConfiguration.getAuthenticationProviders() == null ||
                basicAuthenticationPolicyConfiguration.getAuthenticationProviders().isEmpty()) {
            sendAuthenticationFailure(response, policyChain, "No authentication provider has been provided");
            return;
        }

        // Removing prefix (basic )
        String encodedUsernamePassword = authorizationHeader.substring(6);
        byte[] decodedBytes = Base64.getDecoder().decode(encodedUsernamePassword);
        String decodedUsernamePassword = new String(decodedBytes);

        String username;
        String password = null;

        int separator = decodedUsernamePassword.indexOf(':');
        if (separator > 0) {
            username = decodedUsernamePassword.substring(0, separator);
            password = decodedUsernamePassword.substring(separator + 1);
        } else {
            username = decodedUsernamePassword;
        }

        AtomicBoolean authenticated = new AtomicBoolean(false);

        Iterator<String> authProviders = basicAuthenticationPolicyConfiguration.getAuthenticationProviders().iterator();
        while( !authenticated.get() && authProviders.hasNext()) {
            AuthenticationProviderResource authProvider = executionContext.getComponent(ResourceManager.class).getResource(
                    authProviders.next(), AuthenticationProviderResource.class);

            if (authProvider == null) {
                continue;
            }

            authProvider.authenticate(username, password, new Handler<Authentication>() {
                @Override
                public void handle(Authentication authentication) {
                    // We succeed to authenticate the user
                    if (authentication != null) {
                        executionContext.setAttribute(ExecutionContext.ATTR_USER, authentication.getUsername());
                        request.metrics().setUser(authentication.getUsername());
                        authenticated.set(true);
                        policyChain.doNext(request, response);
                    }
                }
            });
        }

        if (! authenticated.get()) {
            // No authentication provider matched, returning an authentication failure
            sendAuthenticationFailure(response, policyChain);
        }
    }

    private void sendAuthenticationFailure(Response response, PolicyChain policyChain) {
        sendAuthenticationFailure(response, policyChain, "Unauthorized");
    }

    private void sendAuthenticationFailure(Response response, PolicyChain policyChain, String message) {
        String realmName = basicAuthenticationPolicyConfiguration.getRealm();

        if (realmName == null || realmName.trim().isEmpty()) {
            realmName = DEFAULT_REALM_NAME;
        }

        response.headers().set(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"" + realmName + "\"");
        policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, message));
    }
}
