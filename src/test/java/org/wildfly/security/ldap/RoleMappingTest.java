/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.ldap;

import org.junit.Test;
import org.wildfly.security.authz.RoleDecoder;

import static org.junit.Assert.assertEquals;
import static org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder.PrincipalMappingBuilder.Attribute;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RoleMappingTest extends AbstractAttributeMappingTest {

    @Test
    public void testRoleMappingWithMemberOf() throws Exception {
        assertAttributes("userWithMemberOfRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RoleFromBaseDN");
        }, Attribute.from("memberOf").asRdn("CN").to(RoleDecoder.KEY_ROLES)) ;
    }

    @Test
    public void testRoleMappingFromSpecificBaseDN() throws Exception {
        assertAttributes("userWithRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RoleFromRolesOu");
        }, Attribute.fromFilter("ou=Roles,dc=elytron,dc=wildfly,dc=org", "(&(objectClass=groupOfNames)(member={0}))", "CN").to(RoleDecoder.KEY_ROLES)) ;
    }

    @Test
    public void testRoleMappingRecursiveFromBaseDN() throws Exception {
        assertAttributes("userWithRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RoleFromRolesOu", "RoleFromBaseDN");
        }, Attribute.fromFilter("(&(objectClass=groupOfNames)(member={0}))", "CN").to(RoleDecoder.KEY_ROLES));
    }

    @Test
    public void testRoleMappingNoRecursiveOnlyFromBaseDN() throws Exception {
        assertAttributes("userWithRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RoleFromBaseDN");
        }, Attribute.fromFilter("(&(objectClass=groupOfNames)(member={0}))", "CN").to(RoleDecoder.KEY_ROLES));
    }
}
