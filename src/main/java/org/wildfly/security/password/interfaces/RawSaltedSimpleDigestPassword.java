/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.password.interfaces;

class RawSaltedSimpleDigestPassword extends RawPassword implements SaltedSimpleDigestPassword {

    private static final long serialVersionUID = -7933794700841833594L;

    private final byte[] digest;
    private final byte[] salt;

    RawSaltedSimpleDigestPassword(final String algorithm, final byte[] digest, final byte[] salt) {
        super(algorithm);
        this.digest = digest;
        this.salt = salt;
    }

    public byte[] getDigest() {
        return digest.clone();
    }

    public byte[] getSalt() {
        return salt.clone();
    }
}
