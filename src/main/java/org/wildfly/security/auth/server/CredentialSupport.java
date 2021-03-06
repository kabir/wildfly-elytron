/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.server;

import static org.wildfly.security._private.ElytronMessages.log;

import java.util.EnumSet;

/**
 * The level of support for a type of credential.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public enum CredentialSupport {

    /**
     * The given credential type is unsupported for both obtaining the credential and verifying the credential.
     */
    UNSUPPORTED(SupportLevel.UNSUPPORTED, SupportLevel.UNSUPPORTED),

    /**
     * The given credential type may be verifiable but it can not be obtained.
     */
    POSSIBLY_VERIFIABLE(SupportLevel.UNSUPPORTED, SupportLevel.POSSIBLY_SUPPORTED),

    /**
     * The given credential type is possibly obtainable but never verifiable.
     */
    POSSIBLY_OBTAINABLE(SupportLevel.POSSIBLY_SUPPORTED, SupportLevel.UNSUPPORTED),

    /**
     * The given credential type can be obtained but not verified.
     */
    OBTAINABLE_ONLY(SupportLevel.SUPPORTED, SupportLevel.UNSUPPORTED),

    /**
     * The given credential type is definitely verifiable but not obtainable.
     */
    VERIFIABLE_ONLY(SupportLevel.UNSUPPORTED, SupportLevel.SUPPORTED),

    /**
     * The given credential type may be obtainable or verifiable but this is not known for certain.
     */
    UNKNOWN(SupportLevel.POSSIBLY_SUPPORTED, SupportLevel.POSSIBLY_SUPPORTED),

    /**
     * The given credential type is definitely verifiable and maybe obtainable.
     */
    VERIFIABLE_MAYBE_OBTAINABLE(SupportLevel.POSSIBLY_SUPPORTED, SupportLevel.SUPPORTED),

    /**
     * The given credential type is both obtainable and verifiable.
     */
    FULLY_SUPPORTED(SupportLevel.SUPPORTED, SupportLevel.SUPPORTED);

    private final SupportLevel obtainable;
    private final SupportLevel verifiable;

    private CredentialSupport(final SupportLevel obtainable, final SupportLevel verifiable) {
        this.obtainable = obtainable;
        this.verifiable = verifiable;
    }

    /**
     * Obtain the {@link SupportLevel} for being obtainable.
     *
     * @return the {@link SupportLevel} for being obtainable
     */
    public SupportLevel obtainableSupportLevel() {
        return obtainable;
    }

    /**
     * Obtain the {@link SupportLevel} for verification.
     *
     * @return the {@link SupportLevel} for verification
     */
    public SupportLevel verificationSupportLevel() {
        return verifiable;
    }

    /**
     * Determine if this object represents that a credential type is definitely obtainable.
     *
     * @return {@code true} if the credential type is definitely obtainable, {@code false} otherwise.
     */
    public boolean isDefinitelyObtainable() {
        return obtainable.isDefinitelySupported();
    }

    /**
     * Determine if this object represents that a credential type is definitely verifiable.
     *
     * @return {@code true} if the credential type is definitely verifiable, {@code false} otherwise.
     */
    public boolean isDefinitelyVerifiable() {
        return verifiable.isDefinitelySupported();
    }

    /**
     * Determine if this object represents that a credential type is may be obtainable.
     *
     * @return {@code true} if the credential type may be obtainable, {@code false} otherwise.
     */
    public boolean mayBeObtainable() {
        return obtainable.mayBeSupported();
    }

    /**
     * Determine if this object represents that a credential type is may be verifiable.
     *
     * @return {@code true} if the credential type may be verifiable, {@code false} otherwise.
     */
    public boolean mayBeVerifiable() {
        return verifiable.mayBeSupported();
    }

    /**
     * Determine if this object represents that a credential type is not obtainable.
     *
     * @return {@code true} if the credential type is not obtainable, {@code false} otherwise.
     */
    public boolean isNotObtainable() {
        return obtainable.isNotSupported();
    }

    /**
     * Determine if this object represents that a credential type is not verifiable.
     *
     * @return {@code true} if the credential type is not verifiable, {@code false} otherwise.
     */
    public boolean isNotVerifiable() {
        return verifiable.isNotSupported();
    }

    /**
     * Determine if this object represents that a credential type is not supported as all.
     *
     * @return {@code true} if the credential type is not supported at all, {@code false} otherwise.
     */
    public boolean isNotSupported() {
        return isNotObtainable() && isNotVerifiable();
    }

    /**
     * Given the individual {@link SupportLevel} values for a credential type being obtainable and verifiable return the corresponding value of this enumeration.
     *
     * @param obtainable the level of support for obtaining the credential type.
     * @param verifiable the level of support for verifying the credential type.
     * @return The corresponding value of this enumeration.
     * @throws IllegalArgumentException if the arguments form an invalid combination.
     */
    public static CredentialSupport getCredentialSupport(final SupportLevel obtainable, final SupportLevel verifiable) {
        for (CredentialSupport current : values()) {
            if (current.obtainable.equals(obtainable) && current.verifiable.equals(verifiable)) {
                return current;
            }
        }

        throw log.invalidCombinationOfObtainableAndVerifiable();
    }

    private static final int fullSize = values().length;

    /**
     * Determine whether the given set is fully populated (or "full"), meaning it contains all possible values.
     *
     * @param set the set
     *
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<CredentialSupport> set) {
        return set != null && set.size() == fullSize;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final CredentialSupport v1) {
        return this == v1;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final CredentialSupport v1, final CredentialSupport v2) {
        return this == v1 || this == v2;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     * @param v3 the third instance
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final CredentialSupport v1, final CredentialSupport v2, final CredentialSupport v3) {
        return this == v1 || this == v2 || this == v3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the possible values
     *
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final CredentialSupport... values) {
        if (values != null) for (CredentialSupport value : values) {
            if (this == value) return true;
        }
        return false;
    }
}
