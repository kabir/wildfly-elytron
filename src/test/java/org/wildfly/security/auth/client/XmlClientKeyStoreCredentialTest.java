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

import java.io.File;
import java.io.FileOutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
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
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.keystore.WrappingPasswordKeyStore;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * @author Kabir Khan
 */
public class XmlClientKeyStoreCredentialTest {
    private static final Provider wildFlyElytronProvider = new WildFlyElytronProvider();

    //private static final String KEY_STORE_TYPE = "PasswordFile";
    private static final String KEY_STORE_TYPE = "jceks";
    //private static final String KEY_STORE_TYPE = "jks";
    //private static final String KEY_STORE_TYPE = "pkcs12";
    private static final char[] STORE_PASSWORD = null;//"storepassword".toCharArray();


    private ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(STORE_PASSWORD);

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
        File keyStoreFile = getKeyStoreFile();
        final Password password = createKeyStore("test-alias", "test-pwd", keyStoreFile);

        final SecurityFactory<AuthenticationContext> factory =
                ElytronXmlParser.parseAuthenticationClientConfiguration(
                        ConfigurationXMLStreamReader.openUri(this.getClass().getResource("xml-client-key-store-credential.xml").toURI(),
                                XMLInputFactory.newFactory()));
        //TODO rework to
        // create keystore
        // provide keystore in xml
        // reference keystore from config

//        AuthenticationContext ctx =
//                AuthenticationContext.empty().with(
//                        MatchRule.ALL,
//                        AuthenticationConfiguration.EMPTY
//                                .usePassword("test"));
        AuthenticationContext ctx = factory.create();
        CallbackHandler cbh = ClientUtils.getCallbackHandler(new URI("does://not.seem.to.matter"), ctx);

        PasswordCallback passwordCallback = new PasswordCallback("whatever", false);
        cbh.handle(new Callback[]{passwordCallback});

        Assert.assertEquals("test", new String(passwordCallback.getPassword()));
    }

    private File getKeyStoreFile() throws Exception {
        Path path = Paths.get(".", "keystore").normalize();
        Files.createDirectories(path);
        File file = new File(path.toFile(), "xml-client-keystore-credential-test.keystore");
        if (file.exists()) {
            Assert.assertTrue(file.delete());
        }

        return file;
    }

    private Password createKeyStore(String alias, String pwd, File file) throws Exception {
        KeyStore keyStore = new WrappingPasswordKeyStore(KeyStore.getInstance(KEY_STORE_TYPE));

//        keyStore.load(new InputStream() {
//            public int read() throws IOException {
//                return -1;
//            }
//        }, null);
        keyStore.load(null, null);

//        final PasswordFactory passwordFactory = PasswordFactory.getInstance(UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5);
//        byte[] b = new byte[16];
//        ThreadLocalRandom.current().nextBytes(b);
//        final Password password = passwordFactory.generatePassword(new EncryptablePasswordSpec(pwd.toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(16, b)));
//        final PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
//        final Password password = passwordFactory.generatePassword(new ClearPasswordSpec(pwd.toCharArray()));
//        keyStore.setEntry(alias, new PasswordEntry(password), null);
        final Password password = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, pwd.toCharArray());
        keyStore.setEntry(
                alias,
                new PasswordEntry(password),
                new KeyStore.PasswordProtection("".toCharArray()));

        file.delete();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            keyStore.store(fos, STORE_PASSWORD);
        }

        File test = new File("keystore/xml-client-keystore-credential-test.keystore");
        System.out.println(test.getAbsolutePath());

        return password;
    }


}
