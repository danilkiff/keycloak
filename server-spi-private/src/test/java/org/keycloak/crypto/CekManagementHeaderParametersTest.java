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
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.keycloak.models.KeycloakSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests the pure decision logic used when applying provider-owned header parameters for JWE decryption.
 * The session-resolution plumbing in {@link CekManagementHeaderParameters#applyForDecryption} is covered by
 * integration tests.
 */
public class CekManagementHeaderParametersTest {

    @Test
    public void noFactoryYieldsEmptySet() {
        // getProviderFactory returns null for an unknown alg; this must not NPE and must default to empty
        assertTrue(CekManagementHeaderParameters.ownedHeaderParameters(null).isEmpty());
    }

    @Test
    public void factoryWithoutOwnedParametersYieldsEmptySet() {
        CekManagementProviderFactory standard = new TestFactory("RSA-OAEP", Collections.<String>emptySet());
        assertTrue(CekManagementHeaderParameters.ownedHeaderParameters(standard).isEmpty());
    }

    @Test
    public void ownedParametersArePassedThrough() {
        CekManagementProviderFactory factory = new TestFactory("EXAMPLE-KEM", Collections.singleton("urn:example:seed"));
        assertEquals(Collections.singleton("urn:example:seed"), CekManagementHeaderParameters.ownedHeaderParameters(factory));
    }

    @Test
    public void nullOwnedParametersYieldEmptySet() {
        // A non-conforming factory may break the documented "never null" contract; this must not NPE.
        CekManagementProviderFactory misbehaving = new TestFactory("EXAMPLE-KEM", null);
        assertTrue(CekManagementHeaderParameters.ownedHeaderParameters(misbehaving).isEmpty());
    }

    @Test
    public void ownedParametersAreReturnedAsImmutableSnapshot() {
        Set<String> mutable = new HashSet<>();
        mutable.add("urn:example:seed");
        CekManagementProviderFactory factory = new TestFactory("EXAMPLE-KEM", mutable);

        Set<String> owned = CekManagementHeaderParameters.ownedHeaderParameters(factory);

        // Mutating the factory's set afterwards must not change the already-returned snapshot...
        mutable.add("urn:example:other");
        assertEquals(Collections.singleton("urn:example:seed"), owned);

        // ...and the snapshot itself must be immutable.
        try {
            owned.add("x");
            fail("Expected the returned set to be an immutable snapshot");
        } catch (UnsupportedOperationException expected) {
            // expected
        }
    }

    private static final class TestFactory implements CekManagementProviderFactory {
        private final String id;
        private final Set<String> owned;

        TestFactory(String id, Set<String> owned) {
            this.id = id;
            this.owned = owned;
        }

        @Override
        public CekManagementProvider create(KeycloakSession session) {
            return null;
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public Set<String> getProvidedHeaderParameters() {
            return owned;
        }
    }
}
