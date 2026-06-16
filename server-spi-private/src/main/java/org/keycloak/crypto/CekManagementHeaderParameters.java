/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
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
import java.util.LinkedHashSet;
import java.util.Set;

import org.keycloak.jose.JOSEHeader;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderFactory;

/**
 * Applies provider-owned JWE protected header parameters when Keycloak decrypts an inbound JWE.
 * <p>
 * On decode Keycloak must tell the {@link JWE} which extra header parameters the algorithm provider owns, so that
 * only those are captured from the received header. The owned names are declared by the algorithm's
 * {@link CekManagementProviderFactory#getProvidedHeaderParameters()}.
 * <p>
 * Encryption (encode) needs no equivalent step: the algorithm provider writes its parameters directly on the header
 * builder during {@code encodeCek}, and {@code JWE} serializes them.
 */
public final class CekManagementHeaderParameters {

    private CekManagementHeaderParameters() {
    }

    /**
     * Null-safe accessor for the header parameter names owned by a CEK management algorithm. Returns an empty set when
     * the algorithm has no factory (for example an unknown {@code alg}) or declares no owned parameters.
     */
    public static Set<String> ownedHeaderParameters(CekManagementProviderFactory factory) {
        if (factory == null) {
            return Collections.emptySet();
        }
        Set<String> owned = factory.getProvidedHeaderParameters();
        // Null-safe (a non-conforming factory may break the contract) and an immutable snapshot of a possibly shared set.
        if (owned == null || owned.isEmpty()) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(owned));
    }

    /**
     * Declares, on the given JWE, the provider-owned header parameters for its {@code alg}, so that a subsequent
     * {@code verifyAndDecodeJwe()} captures them. No-op when the JWE has no JWE header, no {@code alg}, or its
     * algorithm has no CEK management factory.
     */
    public static void applyForDecryption(KeycloakSession session, JWE jwe) {
        JOSEHeader header = jwe.getHeader();
        if (!(header instanceof JWEHeader)) {
            return;
        }
        String alg = ((JWEHeader) header).getAlgorithm();
        if (alg == null) {
            return;
        }
        ProviderFactory<CekManagementProvider> factory =
                session.getKeycloakSessionFactory().getProviderFactory(CekManagementProvider.class, alg);
        jwe.providedHeaderParameters(ownedHeaderParameters(
                factory instanceof CekManagementProviderFactory ? (CekManagementProviderFactory) factory : null));
    }
}
