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

package org.wildfly.security.auth.server;

import java.security.PermissionCollection;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;
import java.util.concurrent.Callable;

import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;

/**
 * A loaded and authenticated security identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityIdentity {
    private final SecurityDomain securityDomain;
    private final Principal principal;
    private final AuthorizationIdentity authorizationIdentity;
    private final RealmInfo realmInfo;

    SecurityIdentity(final SecurityDomain securityDomain, final Principal principal, final RealmInfo realmInfo, final AuthorizationIdentity authorizationIdentity) {
        this.securityDomain = securityDomain;
        this.principal = principal;
        this.realmInfo = realmInfo;
        this.authorizationIdentity = authorizationIdentity;
    }

    SecurityDomain getSecurityDomain() {
        return securityDomain;
    }

    RealmInfo getRealmInfo() {
        return this.realmInfo;
    }

    AuthorizationIdentity getAuthorizationIdentity() {
        return authorizationIdentity;
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     */
    public void runAs(Runnable action) {
        if (action == null) return;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            action.run();
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws Exception if the action fails
     */
    public <T> T runAs(Callable<T> action) throws Exception {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return action.call();
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     */
    public <T> T runAs(PrivilegedAction<T> action) {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return action.run();
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public <T> T runAs(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return action.run();
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action result (may be {@code null})
     */
    public <T, P> T runAs(P parameter, ParametricPrivilegedAction<T, P> action) {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return action.run(parameter);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public <T, P> T runAs(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return action.run(parameter);
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Get the roles associated with this identity.
     *
     * @return the roles associated with this identity
     */
    public Set<String> getRoles() {
        return this.securityDomain.mapRoles(this);
    }

    /**
     * Get the permissions associated with this identity.
     *
     * @return the permissions associated with this identity
     */
    public PermissionCollection getPermissions() {
        return this.securityDomain.mapPermissions(this);
    }

    /**
     * Get the attributes associated with this identity.
     *
     * @return a read-only instance of {@link Attributes} with all attributes associated with this identity
     */
    public Attributes getAttributes() {
        return this.authorizationIdentity.getAttributes().asReadOnly();
    }

    /**
     * Get the principal of this identity.
     *
     * @return the principal of this identity
     */
    public Principal getPrincipal() {
        return principal;
    }
}
