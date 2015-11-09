/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.security.auth.client;

import java.net.URI;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.xml.stream.XMLInputFactory;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.WildFlyElytronProvider;

/**
 * @author Kabir Khan
 */
public class XmlClearPasswordTest {
    private static final Provider wildFlyElytronProvider = new WildFlyElytronProvider();

    @BeforeClass
    public static void registerProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Integer>() {
            public Integer run() {
                return Security.insertProviderAt(wildFlyElytronProvider, 1);
            }
        });
    }

    @AfterClass
    public static void removeProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Security.removeProvider(wildFlyElytronProvider.getName());

                return null;
            }
        });
    }

    @Test
    public void testKeystoreCredential() throws Exception {
        final SecurityFactory<AuthenticationContext> factory =
                ElytronXmlParser.parseAuthenticationClientConfiguration(
                        ConfigurationXMLStreamReader.openUri(this.getClass().getResource("xml-clear-password.xml").toURI(),
                                XMLInputFactory.newFactory()));
        AuthenticationContext ctx = factory.create();
        CallbackHandler cbh = ClientUtils.getCallbackHandler(new URI("does://not.seem.to.matter"), ctx);

        PasswordCallback passwordCallback = new PasswordCallback("whatever", false);
        cbh.handle(new Callback[]{passwordCallback});

        Assert.assertEquals("MyPasswordFromXml", new String(passwordCallback.getPassword()));
    }
}
