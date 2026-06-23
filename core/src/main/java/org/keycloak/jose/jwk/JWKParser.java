/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.jose.jwk;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyType;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class JWKParser {

    protected JWK jwk;

    private JWKParser() {
    }

    public static JWKParser create() {
        return new JWKParser();
    }

    public JWKParser(JWK jwk) {
        this.jwk = jwk;
    }

    public static JWKParser create(JWK jwk) {
        return new JWKParser(jwk);
    }

    public JWKParser parse(String jwk) {
        try {
            this.jwk = JsonSerialization.mapper.readValue(jwk, JWK.class);
            return this;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public JWK getJwk() {
        return jwk;
    }

    public PublicKey toPublicKey() {
        if (jwk == null) {
            throw new IllegalStateException("Not possible to convert to the publicKey. The jwk is not set");
        }
        String keyType = jwk.getKeyType();

        // subtypes may store properties differently while representing the same JWK, serializing it to nodes
        // makes sure there is no difference when creating the keys
        JsonNode normalizedJwkNode = JsonSerialization.writeValueAsNode(jwk);
        if (KeyType.RSA.equals(keyType)) {
            return createRSAPublicKey(normalizedJwkNode);
        } else if (KeyType.EC.equals(keyType)) {
            return createECPublicKey(normalizedJwkNode);
        } else if (KeyType.OKP.equals(keyType)) {
            return JWKBuilder.EdEC_UTILS.createOKPPublicKey(jwk);
        } else if (KeyType.AKP.equals(keyType)) {
            return createAPKPublicKey(normalizedJwkNode);
        } else {
            throw new RuntimeException("Unsupported keyType " + keyType);
        }
    }

    private static PublicKey createECPublicKey(JsonNode jwk) {


        /* Try retrieving the necessary fields */
        String crv = jwk.path(ECPublicJWK.CRV).asText(null);
        String xStr = jwk.get(ECPublicJWK.X).asText(null);
        String yStr = jwk.get(ECPublicJWK.Y).asText(null);

        /* Check if the retrieving of necessary fields success */
        if (crv == null || xStr == null || yStr == null) {
            throw new RuntimeException("Fail to retrieve ECPublicJWK.CRV, ECPublicJWK.X or ECPublicJWK.Y field.");
        }

        BigInteger x = new BigInteger(1, Base64Url.decode(xStr));
        BigInteger y = new BigInteger(1, Base64Url.decode(yStr));

        String name;
        boolean nonStandardCurve = false;
        switch (crv) {
            case "P-256" :
                name = "secp256r1";
                break;
            case "P-384" :
                name = "secp384r1";
                break;
            case "P-521" :
                name = "secp521r1";
                break;
            default :
                // accept only a curve the active CryptoProvider explicitly advertises. The advertised name
                // must be one the provider can resolve to curve parameters; anything else is rejected
                if (!CryptoIntegration.getProvider().getSupportedECCurves().contains(crv)) {
                    throw new RuntimeException("Unsupported curve");
                }
                name = crv;
                nonStandardCurve = true;
        }

        // createECParams returns null for a curve the active provider does not support
        ECParameterSpec params = CryptoIntegration.getProvider().createECParams(name);
        if (params == null) {
            throw new RuntimeException("Unsupported curve");
        }

        if (nonStandardCurve) {
            // Explicitly validate that the point lies on the curve for a provider-advertised curve, so the
            // guarantee does not depend on the key factory's behavior. P-256/384/521 are unchanged.
            checkPointOnCurve(x, y, params);
        }

        try {

            ECPoint point = new ECPoint(x, y);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);

            KeyFactory kf = CryptoIntegration.getProvider().getKeyFactory("ECDSA");
            return kf.generatePublic(pubKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies that the affine point {@code (x, y)} lies on the prime-field curve described by
     * {@code params} ({@code y^2 == x^3 + a*x + b mod p}, with both coordinates in {@code [0, p)}).
     * Throws if the point is not on the curve, so an invalid point is rejected by core rather than
     * relying on the key factory.
     */
    private static void checkPointOnCurve(BigInteger x, BigInteger y, ECParameterSpec params) {
        EllipticCurve curve = params.getCurve();
        if (!(curve.getField() instanceof ECFieldFp)) {
            // Only prime-field curves can be validated here; reject what cannot be checked.
            throw new RuntimeException("Unsupported curve");
        }
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
            throw new RuntimeException("EC public key point is not on the curve");
        }
        BigInteger lhs = y.modPow(BigInteger.valueOf(2), p);
        BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
                .add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
        if (!lhs.equals(rhs)) {
            throw new RuntimeException("EC public key point is not on the curve");
        }
    }

    private static PublicKey createRSAPublicKey(JsonNode jwk) {
        BigInteger modulus = new BigInteger(1, Base64Url.decode(jwk.path(RSAPublicJWK.MODULUS).asText(null)));
        BigInteger publicExponent = new BigInteger(1, Base64Url.decode(jwk.path(RSAPublicJWK.PUBLIC_EXPONENT).asText(null)));

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey createAPKPublicKey(JsonNode jwk) {
        String algorithm = jwk.path(JWK.ALGORITHM).asText();
        String publicKey = jwk.path(AKPPublicJWK.PUB).asText();
        return AKPUtils.fromEncodedPub(publicKey, algorithm);
    }

    public boolean isKeyTypeSupported(String keyType) {
        return (RSAPublicJWK.RSA.equals(keyType) || ECPublicJWK.EC.equals(keyType)
                || (JWKBuilder.EdEC_UTILS.isEdECSupported() && OKPPublicJWK.OKP.equals(keyType)))
                || KeyType.AKP.equals(keyType);
    }
}
