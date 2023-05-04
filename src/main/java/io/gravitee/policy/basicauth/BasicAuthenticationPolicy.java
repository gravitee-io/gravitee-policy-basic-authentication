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

import static io.gravitee.gateway.api.ExecutionContext.ATTR_API;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.basicauth.configuration.BasicAuthenticationPolicyConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import java.util.Base64;
import java.util.Iterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class BasicAuthenticationPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(BasicAuthenticationPolicy.class);

    /**
     * Basic authentication policy configuration
     */
    private final BasicAuthenticationPolicyConfiguration basicAuthenticationPolicyConfiguration;

    private static final String ERROR_MESSAGE_FORMAT = "[api-id:{}] [request-id:{}] [request-path:{}] {}";
    private static final String INVALID_AUTH_HEADER_ERROR_MESSAGE = "Invalid authorization header";
    private static final String INVALID_CREDENTIALS = "Invalid credentials";

    private static final String BASIC_AUTHENTICATION_VALUE = "BASIC ";
    static final String DEFAULT_REALM_NAME = "gravitee.io";

    private String userAttribute;

    static final String BASIC_AUTH_USER_ATTRIBUTE_KEY = "policy.basic-auth.attributes.user";
    static final String DEFAULT_BASIC_AUTH_USER_ATTRIBUTE = ExecutionContext.ATTR_USER;

    public BasicAuthenticationPolicy(BasicAuthenticationPolicyConfiguration basicAuthenticationPolicyConfiguration) {
        this.basicAuthenticationPolicyConfiguration = basicAuthenticationPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String authorizationHeader = request.headers().getFirst(HttpHeaderNames.AUTHORIZATION);

        if (
            authorizationHeader == null ||
            authorizationHeader.trim().isEmpty() ||
            !authorizationHeader.toUpperCase().startsWith(BASIC_AUTHENTICATION_VALUE)
        ) {
            log(executionContext.getAttribute(ATTR_API), request.id(), request.path(), INVALID_AUTH_HEADER_ERROR_MESSAGE);
            sendAuthenticationFailure(response, policyChain);
            return;
        }

        if (
            basicAuthenticationPolicyConfiguration.getAuthenticationProviders() == null ||
            basicAuthenticationPolicyConfiguration.getAuthenticationProviders().isEmpty()
        ) {
            sendAuthenticationFailure(response, policyChain, "No authentication provider has been provided");
            return;
        }

        // Removing prefix (basic )
        String encodedUsernamePassword = authorizationHeader.substring(6);

        try {
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

            final Iterator<String> providers = basicAuthenticationPolicyConfiguration.getAuthenticationProviders().iterator();

            doAuthenticate(
                username,
                password,
                providers,
                executionContext,
                result -> {
                    if (result == null) {
                        // No authentication provider matched, returning an authentication failure
                        log(executionContext.getAttribute(ATTR_API), request.id(), request.path(), INVALID_CREDENTIALS);

                        sendAuthenticationFailure(response, policyChain);
                    } else {
                        request.metrics().setUser(result);
                        policyChain.doNext(request, response);
                    }
                }
            );
        } catch (IllegalArgumentException iae) {
            log(executionContext.getAttribute(ATTR_API), request.id(), request.path(), INVALID_CREDENTIALS);
            sendAuthenticationFailure(response, policyChain);
        }
    }

    private void doAuthenticate(
        String username,
        String password,
        Iterator<String> providers,
        ExecutionContext context,
        Handler<String> authHandler
    ) {
        if (providers.hasNext()) {
            AuthenticationProviderResource authProvider = context
                .getComponent(ResourceManager.class)
                .getResource(providers.next(), AuthenticationProviderResource.class);

            authProvider.authenticate(
                username,
                password,
                context,
                new Handler<Authentication>() {
                    @Override
                    public void handle(Authentication authentication) {
                        // We succeed to authenticate the user
                        if (authentication != null) {
                            final String userAttribute = getUserAttribute(context);
                            context.setAttribute(userAttribute, authentication.getUsername());

                            // Set the user as part of the metrics for later report
                            context.request().metrics().setUser(authentication.getUsername());

                            // Map user attributes into execution context attributes
                            if (authentication.getAttributes() != null) {
                                authentication
                                    .getAttributes()
                                    .forEach((name, value) -> context.setAttribute(userAttribute + '.' + name, value));
                            }

                            authHandler.handle(authentication.getUsername());
                        } else {
                            //Do next
                            doAuthenticate(username, password, providers, context, authHandler);
                        }
                    }
                }
            );
        } else {
            authHandler.handle(null);
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

        response.headers().set(HttpHeaderNames.WWW_AUTHENTICATE, "Basic realm=\"" + realmName + "\"");
        policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, message));
    }

    private String getUserAttribute(ExecutionContext context) {
        if (userAttribute == null) {
            Environment environment = context.getComponent(Environment.class);
            userAttribute = environment.getProperty(BASIC_AUTH_USER_ATTRIBUTE_KEY, DEFAULT_BASIC_AUTH_USER_ATTRIBUTE);
        }

        return userAttribute;
    }

    private void log(Object... parameters) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(ERROR_MESSAGE_FORMAT, parameters);
        } else if (LOGGER.isWarnEnabled()) {
            LOGGER.warn(ERROR_MESSAGE_FORMAT, parameters);
        }
    }
}
