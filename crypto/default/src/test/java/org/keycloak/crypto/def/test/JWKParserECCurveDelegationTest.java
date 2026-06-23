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
package org.keycloak.crypto.def.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Collections;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.rule.CryptoInitRule;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * {@link JWKParser} no longer hardcodes the EC curves it can parse. Beyond the standard JOSE curves
 * (P-256/384/521) it consults the active {@link CryptoProvider}'s advertised allow-list
 * ({@link CryptoProvider#getSupportedECCurves()}) and resolves the curve via {@code createECParams}.
 *
 * <p>Verified here with a non-NIST curve (brainpoolP256r1) against the default crypto provider: the
 * default advertises none (so core adds no curves on its own and the key is rejected), and a provider
 * that advertises the curve makes the very same JWK parse.</p>
 */
public class JWKParserECCurveDelegationTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    private static CryptoProvider defaultProvider;

    @BeforeClass
    public static void captureDefaultProvider() {
        defaultProvider = CryptoIntegration.getProvider();
    }

    @AfterClass
    public static void restoreDefaultProvider() {
        CryptoIntegration.setProvider(defaultProvider);
    }

    @Test
    public void defaultProviderAdvertisesNoExtraCurvesSoNonStandardCurveIsRejected() {
        CryptoIntegration.setProvider(defaultProvider);
        try {
            JWKParser.create().parse(readResource("brainpool-public-jwk.json")).toPublicKey();
            fail("default provider advertises no curves beyond P-256/384/521; brainpoolP256r1 must be rejected");
        } catch (RuntimeException e) {
            assertTrue("expected 'Unsupported curve', got: " + e.getMessage(),
                    String.valueOf(e.getMessage()).contains("Unsupported curve"));
        }
    }

    @Test
    public void curveAdvertisedByActiveProviderIsAccepted() {
        CryptoIntegration.setProvider(providerAdvertising(defaultProvider, "brainpoolP256r1"));
        try {
            PublicKey key = JWKParser.create().parse(readResource("brainpool-public-jwk.json")).toPublicKey();
            assertNotNull("brainpoolP256r1 must parse once the active provider advertises it", key);
            assertTrue("expected an EC key, got: " + key.getAlgorithm(),
                    key.getAlgorithm().toUpperCase().contains("EC"));
        } finally {
            CryptoIntegration.setProvider(defaultProvider);
        }
    }

    @Test
    public void advertisedButUnresolvableCurveIsRejectedCleanly() {
        // Allow-list desync: a provider advertises a curve its own table cannot resolve. Must reject
        // cleanly ("Unsupported curve"), not fail later with an opaque NPE.
        CryptoIntegration.setProvider(providerAdvertising(defaultProvider, "x-unresolvable-curve"));
        try {
            String jwk = "{\"kty\":\"EC\",\"crv\":\"x-unresolvable-curve\",\"x\":\"AQAB\",\"y\":\"AQAB\"}";
            JWKParser.create().parse(jwk).toPublicKey();
            fail("an advertised curve the provider cannot resolve must be rejected cleanly");
        } catch (RuntimeException e) {
            assertTrue("expected a clean 'Unsupported curve', got: " + e.getMessage(),
                    String.valueOf(e.getMessage()).contains("Unsupported curve"));
        } finally {
            CryptoIntegration.setProvider(defaultProvider);
        }
    }

    @Test
    public void advertisedCurveWithPointNotOnCurveIsRejected() throws Exception {
        // Core explicitly validates the point lies on the curve, independent of the key factory.
        CryptoIntegration.setProvider(providerAdvertising(defaultProvider, "brainpoolP256r1"));
        try {
            ObjectNode jwk = (ObjectNode) JsonSerialization.mapper.readTree(readResource("brainpool-public-jwk.json"));
            byte[] yBytes = Base64Url.decode(jwk.get("y").asText());
            yBytes[yBytes.length - 1] ^= 0x01;   // flip a bit: the point no longer lies on the curve
            jwk.put("y", Base64Url.encode(yBytes));
            try {
                JWKParser.create().parse(jwk.toString()).toPublicKey();
                fail("a point not on the advertised curve must be rejected");
            } catch (RuntimeException e) {
                assertTrue("expected core's point-on-curve rejection, got: " + e.getMessage(),
                        String.valueOf(e.getMessage()).contains("not on the curve"));
            }
        } finally {
            CryptoIntegration.setProvider(defaultProvider);
        }
    }

    /** A CryptoProvider that delegates everything to {@code delegate} but advertises one extra EC curve. */
    private static CryptoProvider providerAdvertising(CryptoProvider delegate, String curve) {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("getSupportedECCurves".equals(method.getName()) && (args == null || args.length == 0)) {
                return Collections.singleton(curve);
            }
            return method.invoke(delegate, args);
        };
        return (CryptoProvider) Proxy.newProxyInstance(
                JWKParserECCurveDelegationTest.class.getClassLoader(),
                new Class<?>[] { CryptoProvider.class }, handler);
    }

    private static String readResource(String name) {
        try (InputStream in = JWKParserECCurveDelegationTest.class.getResourceAsStream(name)) {
            assertNotNull("missing test resource " + name, in);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n;
            while ((n = in.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
