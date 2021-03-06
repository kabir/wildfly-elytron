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

package org.wildfly.security.auth.callback;

import java.io.Serializable;

/**
 * A server-side callback used to inform the callback handler of authentication timeout changes.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class TimeoutUpdateCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -5191354367490287248L;

    /**
     * @serial The new timeout.
     */
    private long timeout;

    /**
     * Construct a new instance.
     *
     * @param the new timeout
     */
    public TimeoutUpdateCallback(final long timeout) {
        this.timeout = timeout;
    }

    /**
     * Get the timeout.
     *
     * @return the new time at which an authentication attempt should time out, in seconds since 1970-01-01T00:00:00Z
     */
    public long getTimeout() {
        return timeout;
    }

    public boolean isOptional() {
        return false;
    }
}
