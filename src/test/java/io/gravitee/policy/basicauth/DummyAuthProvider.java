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

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import java.util.Map;
import java.util.Set;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
public class DummyAuthProvider extends AuthenticationProviderResource<DummyAuthProvider.DummyAuthProviderConfiguration> {

    static Set<String> ALLOWED_USERS = Set.of("dummy-user", "user");

    @Override
    public void authenticate(String username, String password, ExecutionContext context, Handler<Authentication> handler) {
        if (!ALLOWED_USERS.contains(username)) {
            handler.handle(null);
            return;
        }

        final Authentication authentication = new Authentication(username);

        if (password != null && !password.isEmpty()) {
            authentication.setAttributes(Map.of("password-attribute", password));
        }

        handler.handle(authentication);
    }

    class DummyAuthProviderConfiguration implements ResourceConfiguration {}
}
