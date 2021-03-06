/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.provider.jdbc;

import org.wildfly.security.auth.server.CredentialSupport;

import java.sql.ResultSet;

/**
 * A key mapper is responsible to map data from a comlumn in a table to a specific credential type.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface KeyMapper extends ColumnMapper {

    /**
     * Returns the key type supported by this mapper.
     *
     * @return
     */
    Class<?> getKeyType();

    /**
     * <p>Determine whether a given credential is definitely supported, possibly supported (for some identities), or definitely not
     * supported based on the given {@link ResultSet}.
     *
     * <p>In this case the support is defined based on the query result, usually related with a specific account.
     *
     * @param resultSet the result set
     * @return the level of support for a credential based on the given result set
     */
    CredentialSupport getCredentialSupport(ResultSet resultSet);
}
