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
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.JOSE;
import org.keycloak.jose.JOSECriticalHeaders;
import org.keycloak.jose.JOSEHeader;
import org.keycloak.jose.jwe.JWEHeader.JWEHeaderBuilder;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class JWE implements JOSE {

    private JWEHeader header;
    private String base64Header;

    /**
     * Names of the provider-owned protected header parameters that the active algorithm provider has declared as
     * owned. On decode, only these names are captured from the received header into {@link JWEHeader}.
     */
    private Set<String> providedHeaderParameters = Collections.emptySet();

    private JWEKeyStorage keyStorage = new JWEKeyStorage();
    private String base64Cek;

    private byte[] initializationVector;

    private byte[] content;
    private byte[] encryptedContent;

    private byte[] authenticationTag;

    public JWE() {
    }

    public JWE(String jwt) {
        setupJWEHeader(jwt);
    }

    public JWE header(JWEHeader header) {
        this.header = header;
        this.base64Header = null;
        return this;
    }

    /**
     * Declares the set of provider-owned protected header parameter names for this JWE. The caller (typically the
     * server-side decryption code) obtains this from the algorithm provider's factory. On decode, only these names
     * are captured from the received header into {@link JWEHeader}. Anything not in this set is still ignored,
     * exactly as before.
     */
    public JWE providedHeaderParameters(Set<String> providedHeaderParameters) {
        // Defensive immutable snapshot: the caller may pass a shared, mutable set (e.g. a provider factory singleton).
        this.providedHeaderParameters = providedHeaderParameters == null || providedHeaderParameters.isEmpty()
                ? Collections.emptySet()
                : Collections.unmodifiableSet(new LinkedHashSet<>(providedHeaderParameters));
        return this;
    }

    public JOSEHeader getHeader() {
        if (header == null && base64Header != null) {
            try {
                byte[] decodedHeader = Base64Url.decode(base64Header);
                header = JsonSerialization.readValue(decodedHeader, JWEHeader.class);
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }
        }
        return header;
    }

    public String getBase64Header() throws IOException {
        if (base64Header == null && header != null) {
            base64Header = Base64Url.encode(serializeHeader(header));
        }
        return base64Header;
    }

    /**
     * Serializes the protected header to its canonical JSON bytes. Provider-owned parameters (which are not mapped by
     * Jackson) are merged into the header object after the standard parameters. Insertion order is preserved so the
     * output is deterministic. When there are no provider-owned parameters this is byte-for-byte identical to the
     * previous behavior.
     */
    private static byte[] serializeHeader(JWEHeader header) throws IOException {
        Map<String, JsonNode> providerParameters = header.getOtherHeaderParameters();
        if (providerParameters.isEmpty()) {
            return JsonSerialization.writeValueAsBytes(header);
        }
        ObjectNode node = JsonSerialization.mapper.valueToTree(header);
        for (Map.Entry<String, JsonNode> entry : providerParameters.entrySet()) {
            node.set(entry.getKey(), entry.getValue());
        }
        return JsonSerialization.writeValueAsBytes(node);
    }


    public JWEKeyStorage getKeyStorage() {
        return keyStorage;
    }


    public byte[] getInitializationVector() {
        return initializationVector;
    }


    public JWE content(byte[] content) {
        this.content = content;
        return this;
    }

    public byte[] getContent() {
        return content;
    }

    public byte[] getEncryptedContent() {
        return encryptedContent;
    }


    public byte[] getAuthenticationTag() {
        return authenticationTag;
    }


    public void setEncryptedContentInfo(byte[] initializationVector, byte[] encryptedContent, byte[] authenticationTag) {
        this.initializationVector = initializationVector;
        this.encryptedContent = encryptedContent;
        this.authenticationTag = authenticationTag;
    }


    public String encodeJwe() throws JWEException {
        try {
            if (header == null) throw new IllegalStateException("Header must be set");
            return encodeJwe(JWERegistry.getAlgProvider(header.getAlgorithm()), JWERegistry.getEncProvider(header.getEncryptionAlgorithm()));
        } catch (Exception e) {
            throw new JWEException(e);
        }
    }

    public String encodeJwe(JWEAlgorithmProvider algorithmProvider, JWEEncryptionProvider encryptionProvider) throws JWEException {
        try {
            if (header == null) {
                throw new IllegalStateException("Header must be set");
            }
            if (content == null) {
                throw new IllegalStateException("Content must be set");
            }

            if (algorithmProvider == null) {
                throw new IllegalArgumentException("No provider for alg '" + header.getAlgorithm() + "'");
            }

            if (encryptionProvider == null) {
                throw new IllegalArgumentException("No provider for enc '" + header.getEncryptionAlgorithm() + "'");
            }

            keyStorage.setEncryptionProvider(encryptionProvider);
            keyStorage.getCEKKey(JWEKeyStorage.KeyUse.ENCRYPTION, true); // Will generate CEK if it's not already present

            JWEHeaderBuilder headerBuilder = header.toBuilder();
            byte[] encodedCEK = algorithmProvider.encodeCek(encryptionProvider, keyStorage, keyStorage.getEncryptionKey(), headerBuilder);
            base64Cek = Base64Url.encode(encodedCEK);
            header = headerBuilder.build();

            encryptionProvider.encodeJwe(this);

            return getEncodedJweString();
        } catch (Exception e) {
            throw new JWEException(e);
        }
    }

    private String getEncodedJweString() {
        StringBuilder builder = new StringBuilder();
        builder.append(base64Header).append(".")
                .append(base64Cek).append(".")
                .append(Base64Url.encode(initializationVector)).append(".")
                .append(Base64Url.encode(encryptedContent)).append(".")
                .append(Base64Url.encode(authenticationTag));

        return builder.toString();
    }

    private void setupJWEHeader(String jweStr) throws IllegalStateException {
        String[] parts = jweStr.split("\\.");
        if (parts.length != 5) {
            throw new IllegalStateException("Not a JWE String");
        }

        this.base64Header = parts[0];
        this.base64Cek = parts[1];
        this.initializationVector = Base64Url.decode(parts[2]);
        this.encryptedContent = Base64Url.decode(parts[3]);
        this.authenticationTag = Base64Url.decode(parts[4]);

        this.header = (JWEHeader) getHeader();
    }

    private JWE getProcessedJWE(JWEAlgorithmProvider algorithmProvider, JWEEncryptionProvider encryptionProvider) throws Exception {
        if (algorithmProvider == null) {
            throw new IllegalArgumentException("No provider for alg ");
        }

        if (encryptionProvider == null) {
            throw new IllegalArgumentException("No provider for enc ");
        }

        keyStorage.setEncryptionProvider(encryptionProvider);

        processProtectedHeaderParameters();

        byte[] decodedCek = algorithmProvider.decodeCek(Base64Url.decode(base64Cek), keyStorage.getDecryptionKey(), this.header, encryptionProvider);
        keyStorage.setCEKBytes(decodedCek);

        encryptionProvider.verifyAndDecodeJwe(this);

        return this;
    }

    /**
     * Enforces {@code crit} and captures provider-owned protected header parameters from the received header, before
     * the algorithm provider gets to read the header.
     * <p>
     * The raw, received protected header bytes are reparsed here only to read parameter values; the bytes used as AAD
     * for tag verification ({@link #base64Header}) are never recomputed, so the authentication tag stays valid.
     */
    private void processProtectedHeaderParameters() throws Exception {
        if (header == null) {
            return;
        }

        JsonNode rawHeader = JsonSerialization.mapper.readTree(Base64Url.decode(base64Header));

        // RFC 7515 section 4.1.11: reject the token if it relies on a critical parameter we do not understand.
        Set<String> presentHeaderParameters = new HashSet<>();
        Iterator<String> fieldNames = rawHeader.fieldNames();
        while (fieldNames.hasNext()) {
            presentHeaderParameters.add(fieldNames.next());
        }
        String critError = JOSECriticalHeaders.validate(header.getCritical(), presentHeaderParameters,
                JWEHeader.RESERVED_HEADER_PARAMETERS, providedHeaderParameters);
        if (critError != null) {
            throw new JWEException(critError);
        }

        // Capture only the parameters a provider has declared as owned. Everything else stays ignored.
        if (!providedHeaderParameters.isEmpty()) {
            JWEHeaderBuilder builder = null;
            for (String name : providedHeaderParameters) {
                JsonNode value = rawHeader.get(name);
                if (value != null) {
                    if (builder == null) {
                        builder = header.toBuilder();
                    }
                    builder.otherHeaderParameter(name, value);
                }
            }
            if (builder != null) {
                header = builder.build();
            }
        }
    }

    public JWE verifyAndDecodeJwe(String jweStr) throws JWEException {
        try {
            setupJWEHeader(jweStr);
            return verifyAndDecodeJwe();
        } catch (Exception e) {
            throw new JWEException(e);
        }
    }

    public JWE verifyAndDecodeJwe(String jweStr, JWEAlgorithmProvider algorithmProvider, JWEEncryptionProvider encryptionProvider) throws JWEException {
        try {
            setupJWEHeader(jweStr);
            return getProcessedJWE(algorithmProvider, encryptionProvider);
        } catch (Exception e) {
            throw new JWEException(e);
        }
    }

    public JWE verifyAndDecodeJwe() throws JWEException {
        try {
            return getProcessedJWE(JWERegistry.getAlgProvider(header.getAlgorithm()), JWERegistry.getEncProvider(header.getEncryptionAlgorithm()));
        } catch (Exception e) {
            throw new JWEException(e);
        }
    }

}
