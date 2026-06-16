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

package org.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.junit.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.node.ObjectNode;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for {@code crit} (critical header) enforcement on the JWS verification side (RFC 7515 section 4.1.11).
 * A {@code crit} list is for extension parameters only: it must not name a registered JOSE parameter, every entry
 * must be understood by the recipient and present in the protected header, and the list must be well formed.
 */
public class TokenVerifierCriticalHeaderTest {

    private static final String EXT = "urn:example:ext";

    /** Accepts any signature, so the end-to-end tests can focus on header processing without a crypto provider. */
    private static final SignatureVerifierContext ACCEPTING_VERIFIER = new SignatureVerifierContext() {
        @Override
        public String getKid() {
            return null;
        }

        @Override
        public String getAlgorithm() {
            return "HS256";
        }

        @Override
        public boolean verify(byte[] data, byte[] signature) {
            return true;
        }
    };

    // --- the static validator: checkCriticalHeaders(crit, present, understoodExtensions) ---

    @Test
    public void absentCriticalIsAllowed() throws Exception {
        TokenVerifier.checkCriticalHeaders(null, Collections.<String>emptySet(), Collections.<String>emptySet());
    }

    @Test
    public void understoodExtensionPresentIsAllowed() throws Exception {
        TokenVerifier.checkCriticalHeaders(Arrays.asList(EXT), Collections.singleton(EXT), Collections.singleton(EXT));
    }

    @Test(expected = VerificationException.class)
    public void emptyCriticalIsRejected() throws Exception {
        TokenVerifier.checkCriticalHeaders(Collections.<String>emptyList(), Collections.singleton(EXT), Collections.singleton(EXT));
    }

    @Test(expected = VerificationException.class)
    public void emptyCriticalEntryIsRejected() throws Exception {
        TokenVerifier.checkCriticalHeaders(Arrays.asList(""), Collections.singleton(EXT), Collections.singleton(EXT));
    }

    @Test
    public void duplicateCriticalEntryIsRejected() {
        try {
            TokenVerifier.checkCriticalHeaders(Arrays.asList(EXT, EXT), Collections.singleton(EXT), Collections.singleton(EXT));
            fail("Expected VerificationException for a duplicate 'crit' entry");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("duplicate"));
        }
    }

    @Test
    public void registeredHeaderNameInCriticalIsRejected() {
        // "typ" is a registered JOSE parameter and must never appear in crit, even when present and "understood".
        try {
            TokenVerifier.checkCriticalHeaders(Arrays.asList("typ"), Collections.singleton("typ"), Collections.singleton("typ"));
            fail("Expected VerificationException because crit must not list a registered parameter");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("registered"));
        }
    }

    @Test
    public void critListingItselfIsRejected() {
        try {
            TokenVerifier.checkCriticalHeaders(Arrays.asList("crit"), Collections.singleton("crit"), Collections.<String>emptySet());
            fail("Expected VerificationException because 'crit' must not list itself");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("registered"));
        }
    }

    @Test
    public void unknownExtensionIsRejected() {
        try {
            TokenVerifier.checkCriticalHeaders(Arrays.asList(EXT), Collections.singleton(EXT), Collections.singleton("urn:example:other"));
            fail("Expected VerificationException for an unknown critical extension parameter");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("critical"));
        }
    }

    @Test
    public void criticalParameterMissingFromHeaderIsRejected() {
        try {
            TokenVerifier.checkCriticalHeaders(Arrays.asList(EXT), Collections.<String>emptySet(), Collections.singleton(EXT));
            fail("Expected VerificationException because the critical parameter is missing from the header");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("missing from the header"));
        }
    }

    // --- the shared trust-boundary helper: verifyCriticalHeaders(JWSInput[, understoodExtensions]) ---

    @Test
    public void verifyCriticalHeadersIgnoresAbsentCrit() throws Exception {
        TokenVerifier.verifyCriticalHeaders(new JWSInput(jwsWithoutCrit()));
    }

    @Test
    public void verifyCriticalHeadersRejectsAnyCriticalByDefault() throws Exception {
        // No extensions are understood by default, so any critical extension parameter is rejected.
        JWSInput jws = new JWSInput(jws(EXT, true));
        try {
            TokenVerifier.verifyCriticalHeaders(jws);
            fail("Expected VerificationException because no critical extension parameter is understood by default");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("critical"));
        }
    }

    @Test
    public void verifyCriticalHeadersRejectsRegisteredName() throws Exception {
        JWSInput jws = new JWSInput(jws("typ", true));
        try {
            TokenVerifier.verifyCriticalHeaders(jws, Collections.singleton("typ"));
            fail("Expected VerificationException because crit must not list a registered parameter");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("registered"));
        }
    }

    @Test
    public void verifyCriticalHeadersRejectsCriticalMissingFromHeader() throws Exception {
        JWSInput jws = new JWSInput(jws(EXT, false));
        try {
            TokenVerifier.verifyCriticalHeaders(jws, Collections.singleton(EXT));
            fail("Expected VerificationException because the critical parameter is missing from the header");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("missing from the header"));
        }
    }

    @Test
    public void verifyCriticalHeadersAcceptsUnderstoodExtensionThatIsPresent() throws Exception {
        JWSInput jws = new JWSInput(jws(EXT, true));
        TokenVerifier.verifyCriticalHeaders(jws, new HashSet<>(Arrays.asList(EXT)));
    }

    // --- end to end through TokenVerifier.verify() ---

    @Test
    public void verifyRejectsJwsWithCriticalHeaderByDefault() throws Exception {
        String token = jws(EXT, true);
        try {
            TokenVerifier.create(token, JsonWebToken.class).verifierContext(ACCEPTING_VERIFIER).verify();
            fail("Expected VerificationException because the critical header parameter is not understood");
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("critical"));
        }
    }

    @Test
    public void verifyAcceptsCriticalHeaderOnceDeclaredUnderstood() throws Exception {
        String token = jws(EXT, true);

        TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(token, JsonWebToken.class)
                .verifierContext(ACCEPTING_VERIFIER)
                .withUnderstoodCriticalHeaders(Collections.singleton(EXT))
                .verify();

        assertNotNull(verifier.getToken());
        assertTrue(new JWSInput(token).getHeader().getCritical().contains(EXT));
    }

    /**
     * Hand-builds a JWS whose protected header marks {@code critName} as critical. When {@code includeParameter} is
     * true the parameter is also present in the header. The signature is a placeholder.
     */
    private static String jws(String critName, boolean includeParameter) throws Exception {
        ObjectNode header = JsonSerialization.mapper.createObjectNode();
        header.put("alg", "HS256");
        header.putArray("crit").add(critName);
        if (includeParameter) {
            header.put(critName, "present");
        }
        return assemble(header);
    }

    private static String jwsWithoutCrit() throws Exception {
        ObjectNode header = JsonSerialization.mapper.createObjectNode();
        header.put("alg", "HS256");
        return assemble(header);
    }

    private static String assemble(ObjectNode header) throws Exception {
        ObjectNode payload = JsonSerialization.mapper.createObjectNode();
        payload.put("sub", "user");
        return Base64Url.encode(JsonSerialization.writeValueAsBytes(header)) + "."
                + Base64Url.encode(JsonSerialization.writeValueAsBytes(payload)) + "."
                + Base64Url.encode("placeholder-signature".getBytes(StandardCharsets.UTF_8));
    }
}
