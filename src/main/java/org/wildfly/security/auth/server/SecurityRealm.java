/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

/**
 * A single authentication realm. A realm is backed by a single homogeneous store of identities and credentials.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface SecurityRealm {

    /**
     * For the given name create the {@link RealmIdentity} in the context of this security realm. Any validation / name
     * mapping is an implementation detail for the realm.
     * <p>
     * A realm returning a {@link RealmIdentity} does not confirm the existence of an identity, a realm may also return
     * {@code null} from this method if the provided {code name} can not be mapped to an identity although this is not required
     * of the realm.
     *
     * @param name the name to use when creating the {@link RealmIdentity}
     * @return the {@link RealmIdentity} for the provided {@code name} or {@code null}
     */
    RealmIdentity createRealmIdentity(String name) throws RealmUnavailableException;

    /**
     * Determine whether a given credential is definitely supported, possibly supported (for some identities), or definitely not
     * supported.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialType the credential type
     * @param algorithmName the optional algorithm name for the credential type
     * @return the level of support for this credential type
     */
    CredentialSupport getCredentialSupport(Class<?> credentialType, String algorithmName) throws RealmUnavailableException;

    /**
     * An empty security realm.
     */
    SecurityRealm EMPTY_REALM = new SecurityRealm() {
        public RealmIdentity createRealmIdentity(final String name) throws RealmUnavailableException {
            return RealmIdentity.nonExistentIdentity(name);
        }

        public CredentialSupport getCredentialSupport(final Class<?> credentialType, final String algorithmName) throws RealmUnavailableException {
            return CredentialSupport.UNSUPPORTED;
        }
    };
}
