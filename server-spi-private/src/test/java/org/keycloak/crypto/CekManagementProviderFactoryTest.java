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
import java.util.Set;

import org.junit.Test;
import org.keycloak.models.KeycloakSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Verifies the {@link CekManagementProviderFactory#getProvidedHeaderParameters()} contract: standard algorithms own
 * no extra header parameters by default, while an external algorithm can declare the parameters it owns.
 */
public class CekManagementProviderFactoryTest {

    private static abstract class TestFactory implements CekManagementProviderFactory {
        @Override
        public CekManagementProvider create(KeycloakSession session) {
            return null;
        }
    }

    @Test
    public void defaultIsEmpty() {
        CekManagementProviderFactory factory = new TestFactory() {
            @Override
            public String getId() {
                return "standard";
            }
        };

        assertTrue(factory.getProvidedHeaderParameters().isEmpty());
    }

    @Test
    public void externalFactoryDeclaresItsOwnedParameters() {
        CekManagementProviderFactory factory = new TestFactory() {
            @Override
            public String getId() {
                return "EXAMPLE-KEM";
            }

            @Override
            public Set<String> getProvidedHeaderParameters() {
                return Collections.singleton("urn:example:seed");
            }
        };

        assertEquals(Collections.singleton("urn:example:seed"), factory.getProvidedHeaderParameters());
    }
}
