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

package org.keycloak.jose;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared validation of the {@code crit} (critical) JOSE header parameter (RFC 7515 section 4.1.11), used by both the
 * JWS ({@code TokenVerifier}) and JWE ({@code JWE}) paths so the rules cannot drift apart.
 */
public final class JOSECriticalHeaders {

    private JOSECriticalHeaders() {
    }

    /**
     * Validates a {@code crit} list. The list (when present) must not be empty, must not contain an empty or duplicate
     * entry, must not name a registered JOSE parameter (it is for extensions only), and every entry must be both
     * understood by the recipient and present in the protected header.
     *
     * @param critical the {@code crit} value, or {@code null} if absent
     * @param presentHeaderParameters the parameter names actually present in the protected header
     * @param reserved the registered JOSE header parameter names that must not appear in {@code crit}
     * @param understood the extension parameter names the recipient understands
     * @return {@code null} if the {@code crit} list is valid (or absent), otherwise a human-readable rejection reason
     */
    public static String validate(List<String> critical, Collection<String> presentHeaderParameters,
            Set<String> reserved, Set<String> understood) {
        if (critical == null) {
            return null;
        }
        if (critical.isEmpty()) {
            return "Invalid 'crit' header parameter: it must not be empty when present";
        }
        Set<String> seen = new HashSet<>();
        for (String name : critical) {
            if (name == null || name.isEmpty()) {
                return "Invalid 'crit' header parameter: it must not contain empty entries";
            }
            if (!seen.add(name)) {
                return "Invalid 'crit' header parameter: duplicate entry '" + name + "'";
            }
            if (reserved.contains(name)) {
                return "Invalid 'crit' header parameter: it must not list the registered header parameter '" + name + "'";
            }
            if (!understood.contains(name)) {
                return "Unsupported critical header parameter: " + name;
            }
            if (!presentHeaderParameters.contains(name)) {
                return "Critical header parameter '" + name + "' is listed in 'crit' but missing from the header";
            }
        }
        return null;
    }
}
