/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.jose.JOSEHeader;
import org.keycloak.jose.jwk.ECPublicJWK;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class JWEHeader implements JOSEHeader {

    /**
     * Registered JWE header parameter names (RFC 7516 section 4.1) plus the algorithm-specific names of RFC 7518
     * (sections 4.6.1, 4.7.1, 4.8.1). A provider-owned parameter must not reuse one of these, and {@code crit} must
     * not list one, so a provider cannot claim a standard header name as its own.
     */
    static final Set<String> RESERVED_HEADER_PARAMETERS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
            "epk", "apu", "apv", "iv", "tag", "p2s", "p2c")));

    @JsonProperty("alg")
    private String algorithm;

    @JsonProperty("enc")
    private String encryptionAlgorithm;

    @JsonProperty("zip")
    private String compressionAlgorithm;

    @JsonProperty("typ")
    private String type;

    @JsonProperty("cty")
    private String contentType;

    @JsonProperty("kid")
    private String keyId;

    @JsonProperty("epk")
    private ECPublicJWK ephemeralPublicKey;

    @JsonProperty("apu")
    private String agreementPartyUInfo;

    @JsonProperty("apv")
    private String agreementPartyVInfo;

    @JsonProperty("crit")
    private List<String> critical;

    /**
     * Extra protected header parameters owned by a {@link org.keycloak.jose.jwe.alg.JWEAlgorithmProvider}.
     * <p>
     * These are intentionally NOT (de)serialized by Jackson. Auto-mapping (such as {@code @JsonAnySetter}) would
     * make it too easy to accept attacker-controlled header fields by accident. Instead, {@link JWE} serializes the
     * parameters present here on encode, and on decode only populates the names a provider has explicitly declared as
     * owned (its allow-list). See {@link JWE#providedHeaderParameters(java.util.Set)}.
     */
    @JsonIgnore
    private Map<String, JsonNode> otherHeaderParameters;

    public JWEHeader() {
    }

    public JWEHeader(String algorithm, String encryptionAlgorithm, String compressionAlgorithm) {
        this.algorithm = algorithm;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
    }

    public JWEHeader(String algorithm, String encryptionAlgorithm, String compressionAlgorithm, String keyId) {
        this.algorithm = algorithm;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.keyId = keyId;
    }

    public JWEHeader(String algorithm, String encryptionAlgorithm, String compressionAlgorithm, String keyId, String contentType) {
        this.algorithm = algorithm;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.keyId = keyId;
        this.contentType = contentType;
    }

    public JWEHeader(String algorithm, String encryptionAlgorithm, String compressionAlgorithm, String keyId, String contentType, 
            String type, ECPublicJWK ephemeralPublicKey, String agreementPartyUInfo, String agreementPartyVInfo) {
        this.algorithm = algorithm;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.keyId = keyId;
        this.type = type;
        this.contentType = contentType;
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.agreementPartyUInfo = agreementPartyUInfo;
        this.agreementPartyVInfo = agreementPartyVInfo;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    @JsonIgnore
    @Override
    public String getRawAlgorithm() {
        return getAlgorithm();
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public String getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public String getType() {
        return type;
    }

    public String getContentType() {
        return contentType;
    }

    public String getKeyId() {
        return keyId;
    }

    public ECPublicJWK getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public String getAgreementPartyUInfo() {
        return agreementPartyUInfo;
    }

    public String getAgreementPartyVInfo() {
        return agreementPartyVInfo;
    }

    /**
     * @return the {@code crit} (critical) header parameter as defined by RFC 7515 section 4.1.11, or {@code null}.
     */
    public List<String> getCritical() {
        return critical;
    }

    /**
     * @return the provider-owned protected header parameters, never {@code null}. See {@link #otherHeaderParameters}.
     */
    @JsonIgnore
    public Map<String, JsonNode> getOtherHeaderParameters() {
        return otherHeaderParameters == null ? Collections.emptyMap() : otherHeaderParameters;
    }

    /**
     * @return the value of a single provider-owned protected header parameter, or {@code null} if not present.
     */
    public JsonNode getOtherHeaderParameter(String name) {
        return otherHeaderParameters == null ? null : otherHeaderParameters.get(name);
    }

    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public String toString() {
        try {
            return mapper.writeValueAsString(this);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public JWEHeaderBuilder toBuilder() {
        return builder().algorithm(algorithm).encryptionAlgorithm(encryptionAlgorithm)
                .compressionAlgorithm(compressionAlgorithm).type(type).contentType(contentType)
                .keyId(keyId).ephemeralPublicKey(ephemeralPublicKey).agreementPartyUInfo(agreementPartyUInfo)
                .agreementPartyVInfo(agreementPartyVInfo).critical(critical).otherHeaderParameters(otherHeaderParameters);
    }

    public static JWEHeaderBuilder builder() {
        return new JWEHeaderBuilder();
    }

    public static class JWEHeaderBuilder {
        private String algorithm = null;
        private String encryptionAlgorithm = null;
        private String compressionAlgorithm = null;
        private String type = null;
        private String contentType = null;
        private String keyId = null;
        private ECPublicJWK ephemeralPublicKey = null;
        private String agreementPartyUInfo = null;
        private String agreementPartyVInfo = null;
        private List<String> critical = null;
        private Map<String, JsonNode> otherHeaderParameters = null;

        public JWEHeaderBuilder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public JWEHeaderBuilder encryptionAlgorithm(String encryptionAlgorithm) {
            this.encryptionAlgorithm = encryptionAlgorithm;
            return this;
        }

        public JWEHeaderBuilder compressionAlgorithm(String compressionAlgorithm) {
            this.compressionAlgorithm = compressionAlgorithm;
            return this;
        }

        public JWEHeaderBuilder type(String type) {
            this.type = type;
            return this;
        }

        public JWEHeaderBuilder contentType(String contentType) {
            this.contentType = contentType;
            return this;
        }

        public JWEHeaderBuilder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public JWEHeaderBuilder ephemeralPublicKey(ECPublicJWK ephemeralPublicKey) {
            this.ephemeralPublicKey = ephemeralPublicKey;
            return this;
        }

        public JWEHeaderBuilder agreementPartyUInfo(String agreementPartyUInfo) {
            this.agreementPartyUInfo = agreementPartyUInfo;
            return this;
        }

        public JWEHeaderBuilder agreementPartyVInfo(String agreementPartyVInfo) {
            this.agreementPartyVInfo = agreementPartyVInfo;
            return this;
        }

        public JWEHeaderBuilder critical(List<String> critical) {
            this.critical = critical;
            return this;
        }

        /**
         * Marks a single header parameter name as critical ({@code crit}), creating the list if needed.
         */
        public JWEHeaderBuilder addCritical(String name) {
            if (critical == null) {
                critical = new java.util.ArrayList<>();
            }
            if (!critical.contains(name)) {
                critical.add(name);
            }
            return this;
        }

        public JWEHeaderBuilder otherHeaderParameters(Map<String, JsonNode> otherHeaderParameters) {
            // Route every entry through the guarded single setter so a reserved name cannot slip in via the bulk path.
            this.otherHeaderParameters = null;
            if (otherHeaderParameters != null) {
                for (Map.Entry<String, JsonNode> entry : otherHeaderParameters.entrySet()) {
                    otherHeaderParameter(entry.getKey(), entry.getValue());
                }
            }
            return this;
        }

        /**
         * Sets a single provider-owned protected header parameter, creating the map if needed.
         * Insertion order is preserved so that serialization is deterministic.
         */
        public JWEHeaderBuilder otherHeaderParameter(String name, JsonNode value) {
            if (RESERVED_HEADER_PARAMETERS.contains(name)) {
                throw new IllegalArgumentException("Provider-owned header parameter '" + name
                        + "' must not reuse a registered JOSE protected header parameter name");
            }
            if (otherHeaderParameters == null) {
                otherHeaderParameters = new LinkedHashMap<>();
            }
            otherHeaderParameters.put(name, value);
            return this;
        }

        public JWEHeader build() {
            JWEHeader header = new JWEHeader(algorithm, encryptionAlgorithm, compressionAlgorithm, keyId, contentType,
                    type, ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo);
            header.critical = critical;
            header.otherHeaderParameters = otherHeaderParameters;
            return header;
        }
    }
}
