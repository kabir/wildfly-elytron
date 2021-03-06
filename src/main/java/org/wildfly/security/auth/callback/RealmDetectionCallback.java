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

package org.wildfly.security.auth.callback;

import java.io.Serializable;

/**
 * A callback used to detect the user realm in advance.  Handlers should not be interactive.
 */
public final class RealmDetectionCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -5562791262784911074L;

    /**
     * @serial The realm name.
     */
    private String realm;

    /**
     * Construct a new instance.
     *
     * @param realm the realm name
     */
    public RealmDetectionCallback(final String realm) {
        this.realm = realm;
    }

    /**
     * Construct a new instance with no realm name.
     */
    public RealmDetectionCallback() {
    }

    /**
     * Get the realm name.
     *
     * @return the realm name
     */
    public String getRealm() {
        return realm;
    }

    public boolean needsInformation() {
        return true;
    }
}
