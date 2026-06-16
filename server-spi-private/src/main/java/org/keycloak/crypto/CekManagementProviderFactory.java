/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.crypto;

import java.util.Collections;
import java.util.Set;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;

public interface CekManagementProviderFactory extends ProviderFactory<CekManagementProvider> {

    @Override
    default void init(Config.Scope config) {
    }

    @Override
    default void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    default void close() {
    }

    /**
     * The names of the extra protected JWE header parameters this algorithm owns, beyond the standard JOSE parameters.
     * <p>
     * On encode, the algorithm provider writes these via the {@link org.keycloak.jose.jwe.JWEHeader.JWEHeaderBuilder}.
     * On decode, only the names returned here are captured from the received header into the
     * {@link org.keycloak.jose.jwe.JWEHeader}; any other unknown parameter stays ignored. The set must be stable for
     * a given algorithm.
     * <p>
     * The default is empty, so standard algorithms (RSA, AES, ECDH-ES) are unaffected. External providers (for
     * example a post-quantum KEM or another non-standard algorithm profile) override this to declare the one extra
     * parameter they need.
     *
     * @return the owned header parameter names, never {@code null}
     */
    default Set<String> getProvidedHeaderParameters() {
        return Collections.emptySet();
    }

}
