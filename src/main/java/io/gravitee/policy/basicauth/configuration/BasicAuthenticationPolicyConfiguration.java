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
package io.gravitee.policy.basicauth.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import java.util.List;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class BasicAuthenticationPolicyConfiguration implements PolicyConfiguration {

    private List<String> authenticationProviders;

    private String realm;

    private boolean removeHeader;

    public List<String> getAuthenticationProviders() {
        return authenticationProviders;
    }

    public void setAuthenticationProviders(List<String> authenticationProviders) {
        this.authenticationProviders = authenticationProviders;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public boolean isRemoveHeader() {
        return removeHeader;
    }

    public void setRemoveHeader(boolean removeHeader) {
        this.removeHeader = removeHeader;
    }
}
