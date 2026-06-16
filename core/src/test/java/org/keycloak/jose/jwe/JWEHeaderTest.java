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

package org.keycloak.jose.jwe;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit tests for the provider-owned JWE protected header parameters on the {@link JWEHeader} model.
 * This does not require a crypto provider, so it can run directly in keycloak-core.
 */
public class JWEHeaderTest {

    @Test
    public void reservedHeaderParameterNameIsRejected() {
        // A provider must not reuse a registered JOSE protected header parameter name.
        try {
            JWEHeader.builder().otherHeaderParameter("alg", TextNode.valueOf("x"));
            fail("Expected IllegalArgumentException for a reserved header parameter name");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

    @Test
    public void builderCarriesProviderParameters() {
        JWEHeader header = JWEHeader.builder()
                .algorithm("EXAMPLE-KEM")
                .encryptionAlgorithm("EXAMPLE-ENC")
                .otherHeaderParameter("urn:example:seed", TextNode.valueOf("AAECAwQFBgc"))
                .build();

        assertEquals("AAECAwQFBgc", header.getOtherHeaderParameter("urn:example:seed").asText());
        assertEquals(1, header.getOtherHeaderParameters().size());
    }

    @Test
    public void toBuilderRoundTripsProviderParameters() {
        JWEHeader original = JWEHeader.builder()
                .algorithm("EXAMPLE-KEM")
                .otherHeaderParameter("urn:example:seed", TextNode.valueOf("seed-value"))
                .build();

        JWEHeader copy = original.toBuilder().build();

        assertEquals("seed-value", copy.getOtherHeaderParameter("urn:example:seed").asText());
    }

    @Test
    public void emptyAccessorsAreSafe() {
        JWEHeader header = JWEHeader.builder().algorithm("dir").build();

        assertNotNull(header.getOtherHeaderParameters());
        assertTrue(header.getOtherHeaderParameters().isEmpty());
        assertNull(header.getOtherHeaderParameter("anything"));
    }

    @Test
    public void providerParametersAreNotAutoSerialized() throws Exception {
        JWEHeader header = JWEHeader.builder()
                .algorithm("EXAMPLE-KEM")
                .encryptionAlgorithm("EXAMPLE-ENC")
                .otherHeaderParameter("urn:example:seed", TextNode.valueOf("seed-value"))
                .build();

        String json = JsonSerialization.writeValueAsString(header);

        // The provider-owned VALUE must NOT be emitted by the header model; JWE is responsible for merging it
        // into the protected header. This guards against an accidental @JsonAnyGetter-style leak.
        assertFalse("provider parameter value must not be auto-serialized", json.contains("seed-value"));
    }

    @Test
    public void unknownHeaderParametersAreNotCapturedByTheModel() throws Exception {
        // The model never captures unknown fields on its own (no @JsonAnySetter). Capture is JWE's job,
        // gated by a provider allow-list. Parsing an unknown field must therefore drop it silently.
        String json = "{\"alg\":\"EXAMPLE-KEM\",\"enc\":\"EXAMPLE-ENC\",\"urn:example:seed\":\"seed-value\"}";

        JWEHeader header = JsonSerialization.readValue(json, JWEHeader.class);

        assertEquals("EXAMPLE-KEM", header.getAlgorithm());
        assertNull(header.getOtherHeaderParameter("urn:example:seed"));
        assertTrue(header.getOtherHeaderParameters().isEmpty());
    }

    @Test
    public void bulkOtherHeaderParametersRejectReservedName() {
        // The bulk setter must reject a reserved name, just like the single-parameter setter.
        Map<String, JsonNode> params = new LinkedHashMap<>();
        params.put("alg", TextNode.valueOf("attacker-controlled"));
        try {
            JWEHeader.builder().otherHeaderParameters(params);
            fail("Expected IllegalArgumentException: the bulk setter must reject a reserved header parameter name");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }
}
