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

package org.wildfly.security.sasl.otp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_MD5;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA1;
import static org.wildfly.security.sasl.otp.OTP.HEX_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.INIT_HEX_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.INIT_WORD_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.WORD_RESPONSE;
import static org.wildfly.security.sasl.otp.OTPUtil.getResponseTypeChoiceIndex;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.test.SaslServerBuilder.BuilderReference;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.util.CodePointIterator;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

/**
 * Client and server side tests for the OTP SASL mechanism. The expected results for
 * these test cases were generated using the {@code python-otp} module.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@RunWith(JMockit.class)
public class _NewOTPTest extends BaseTestCase {

    private long timeout;

    @After
    public void dispose() throws Exception {
        timeout = 0L;
    }


    // -- Successful authentication exchanges --

    @Test
    public void testSimpleMD5AuthenticationWithPassPhrase() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;

        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);


        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 499));

        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(HEX_RESPONSE),
                        false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);
            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("hex:5bf075d9959d036f", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testSimpleSHA1AuthenticationWithPassPhrase() throws Exception {
        final String algorithm = ALGORITHM_OTP_SHA1;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("103029b112deb117").hexDecode().drain(),
                "TeSt".getBytes(StandardCharsets.US_ASCII), 100));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("87fec7768b73ccf9").hexDecode().drain(),
                "TeSt".getBytes(StandardCharsets.US_ASCII), 99));

        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(HEX_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);
            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-sha1 99 TeSt ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("hex:87fec7768b73ccf9", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testSimpleMD5AuthenticationWithMultiWordOTP() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "BOND FOGY DRAB NE RISE MART", ResponseFormat.MULTIWORD, getResponseTypeChoiceIndex(WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("word:BOND FOGY DRAB NE RISE MART", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testSimpleSHA1AuthenticationWithMultiWordOTP() throws Exception {
        final String algorithm = ALGORITHM_OTP_SHA1;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("103029b112deb117").hexDecode().drain(),
                "TeSt".getBytes(StandardCharsets.US_ASCII), 100));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("87fec7768b73ccf9").hexDecode().drain(),
                "TeSt".getBytes(StandardCharsets.US_ASCII), 99));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "GAFF WAIT SKID GIG SKY EYED", ResponseFormat.MULTIWORD, getResponseTypeChoiceIndex(WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-sha1 99 TeSt ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("word:GAFF WAIT SKID GIG SKY EYED", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithInitHexResponse() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("3712dcb4aa5316c1").hexDecode().drain(),
                "ke1235".getBytes(StandardCharsets.US_ASCII), 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(INIT_HEX_RESPONSE),
                            false, null, "ke1235".getBytes(StandardCharsets.UTF_8), "3712dcb4aa5316c1");
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("init-hex:5bf075d9959d036f:md5 499 ke1235:3712dcb4aa5316c1", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithInitWordResponse() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("3712dcb4aa5316c1").hexDecode().drain(),
                "ke1235".getBytes(StandardCharsets.US_ASCII), 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(INIT_WORD_RESPONSE),
                            false, null, "ke1235".getBytes(StandardCharsets.UTF_8), "RED HERD NOW BEAN PA BURG");
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("init-word:BOND FOGY DRAB NE RISE MART:md5 499 ke1235:RED HERD NOW BEAN PA BURG", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithLowSequenceNumber() throws Exception {
        mockSeed("lr4321");
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("eb65a876fd5e5e8e").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 10)); // Low sequence number, the sequence should be reset
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("870c2dcc4fd6b474").hexDecode().drain(),
                "lr4321".getBytes(StandardCharsets.US_ASCII), 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, -1,
                            true, "My new pass phrase", null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 9 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("init-word:HOYT ATE SARA DISH REED OUST:md5 499 lr4321:FULL BUSS DIET ITCH CORK SAM", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }


    @Test
    public void testAuthenticationWithMultiWordOTPWithAlternateDictionary() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            Map<String, Object> props = new HashMap<String, Object>();
            props.put(WildFlySasl.OTP_ALTERNATE_DICTIONARY, OTPSaslClientFactory.dictionaryArrayToProperty(OTPTest.ALTERNATE_DICTIONARY));
            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "sars zike zub sahn siar pft", ResponseFormat.MULTIWORD, getResponseTypeChoiceIndex(WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    props, handler);


            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("word:sars zike zub sahn siar pft", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }


    @Test
    public void testAuthenticationWithPassPhraseWithAlternateDictionary() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslServerFactory serverFactory = obtainSaslServerFactory(OTPSaslServerFactory.class);
        assertNotNull(serverFactory);
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            Map<String, Object> props = new HashMap<String, Object>();
            props.put(WildFlySasl.OTP_ALTERNATE_DICTIONARY, OTPSaslClientFactory.dictionaryArrayToProperty(OTPTest.ALTERNATE_DICTIONARY));
            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    props, handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("word:sars zike zub sahn siar pft", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testMultipleSimultaneousAuthenticationSessions() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();

        final SaslServerBuilder serverBuilder1 = createSaslServerBuilder(password, closeableReference, securityDomainReference);
        try {
            final SaslServer saslServer1 = serverBuilder1.build();
            final SaslServer saslServer2 = serverBuilder1.copy(true).build();

            final CallbackHandler handler1 =
                    createClientCallbackHandler(algorithm, "userName", "BOND FOGY DRAB NE RISE MART", ResponseFormat.MULTIWORD, getResponseTypeChoiceIndex(WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient1 = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.emptyMap(), handler1);
            final CallbackHandler handler2 =
                    createClientCallbackHandler(algorithm, "userName", "BOND FOGY DRAB NE RISE MART", ResponseFormat.MULTIWORD, getResponseTypeChoiceIndex(WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient2 = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.emptyMap(), handler2);


            byte[] message1 = saslClient1.evaluateChallenge(new byte[0]);
            assertFalse(saslClient1.isComplete());
            assertFalse(saslServer1.isComplete());

            byte[] message2 = saslClient2.evaluateChallenge(new byte[0]);
            assertFalse(saslClient2.isComplete());
            assertFalse(saslServer2.isComplete());

            message1 = saslServer1.evaluateResponse(message1);
            assertEquals("otp-md5 499 ke1234 ext", new String(message1, StandardCharsets.UTF_8));
            assertFalse(saslServer1.isComplete());
            assertFalse(saslClient1.isComplete());

            try {
                saslServer2.evaluateResponse(message2);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }

            // The first authentication attempt should still succeed
            message1 = saslClient1.evaluateChallenge(message1);
            assertEquals("word:BOND FOGY DRAB NE RISE MART", new String(message1, StandardCharsets.UTF_8));
            assertTrue(saslClient1.isComplete());
            assertFalse(saslServer1.isComplete());

            message1 = saslServer1.evaluateResponse(message1);
            assertTrue(saslServer1.isComplete());
            assertNull(message1);
            assertEquals("userName", saslServer1.getAuthorizationID());

            //Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }


    // -- Unsuccessful authentication exchanges --

    @Test
    public void testAuthenticationWithWrongPassword() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, null);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "TONE NELL RACY GRIN ROOM GELD", ResponseFormat.MULTIWORD, getResponseTypeChoiceIndex(WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            try {
                message = saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithWrongPasswordInInitResponse() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, null);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "GAFF WAIT SKID GIG SKY EYED", ResponseFormat.MULTIWORD, getResponseTypeChoiceIndex(WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            message = saslClient.evaluateChallenge(message);
            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithInvalidNewPasswordInInitResponse() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, null);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "BOND FOGY DRAB NE RISE MART", ResponseFormat.MULTIWORD, getResponseTypeChoiceIndex(INIT_WORD_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));

            // Construct an init-word response with a valid current OTP but an invalid new OTP
            message = "init-word:BOND FOGY DRAB NE RISE MART:md5 0 !ke1235$:RED".getBytes(StandardCharsets.UTF_8);
            try {
                message = saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithInvalidPassPhrase() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 500));
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, null);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "tooShort", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(HEX_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            try {
                saslClient.evaluateChallenge(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithLongSeed() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "thisSeedIsTooLong".getBytes(StandardCharsets.US_ASCII), 500));
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, null);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(HEX_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithNonAlphanumericSeed() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;

        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "A seed!".getBytes(StandardCharsets.US_ASCII), 500));
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, null);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(HEX_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
        }finally {
            closeableReference.getReference().close();
        }
    }


    @Test
    public void testAuthenticationWithInvalidSequenceNumber() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234".getBytes(StandardCharsets.US_ASCII), 0));
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, null);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(HEX_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
        }finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testUnauthorizedAuthorizationId() throws Exception {
        final String algorithm = ALGORITHM_OTP_SHA1;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("103029b112deb117").hexDecode().drain(),
                "TeSt".getBytes(StandardCharsets.US_ASCII), 100));
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, null);

            final CallbackHandler handler =
                    createClientCallbackHandler(algorithm, "userName", "This is a test.", ResponseFormat.PASSPHRASE, getResponseTypeChoiceIndex(HEX_RESPONSE),
                            false, null, null, null);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, "wrongName", "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), handler);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            message = saslClient.evaluateChallenge(message);
            try {
                message = saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
        }finally {
            closeableReference.getReference().close();
        }
    }

    private SaslServerBuilder createSaslServerBuilder(Password password, BuilderReference<Closeable> closeableReference, BuilderReference<SecurityDomain> securityDomainReference) {
        SaslServerBuilder builder = new SaslServerBuilder(OTPSaslServerFactory.class, SaslMechanismInformation.Names.OTP)
                .setModifiableRealm()
                .setUserName("userName")
                .setPassword(password)
                .setModifiableRealm()
                .setProtocol("test")
                .setServerName("testserver1.example.com")
                .registerCloseableReference(closeableReference)
                .registerSecurityDomainReference(securityDomainReference);
        return builder;
    }

    private SaslServer createSaslServer(Password password, BuilderReference<Closeable> closeableReference, BuilderReference<SecurityDomain> securityDomainReference) throws IOException {
        SaslServer saslServer = createSaslServerBuilder(password, closeableReference, securityDomainReference)
                .build();
        assertFalse(saslServer.isComplete());
        return saslServer;
    }

    private void checkPassword(BuilderReference<SecurityDomain> domainReference, String userName,
                               OneTimePassword expectedUpdatedPassword, String algorithmName) throws RealmUnavailableException {
        SecurityDomain securityDomain = domainReference.getReference();
        RealmIdentity securityRealm = securityDomain.mapName(userName);
        OneTimePassword updatedPassword = securityRealm.getCredential(OneTimePassword.class, algorithmName);

        assertEquals(expectedUpdatedPassword.getAlgorithm(), updatedPassword.getAlgorithm());
        assertArrayEquals(expectedUpdatedPassword.getHash(), updatedPassword.getHash());
        assertArrayEquals(expectedUpdatedPassword.getSeed(), updatedPassword.getSeed());
        assertEquals(expectedUpdatedPassword.getSequenceNumber(), updatedPassword.getSequenceNumber());
    }

    private void mockSeed(final String randomStr){
        new MockUp<OTPUtil>(){
            @Mock
            String generateRandomAlphanumericString(int length, Random random){
                return randomStr;
            }
        };
    }

    private enum ResponseFormat {
        PASSPHRASE,
        MULTIWORD
    }

    private CallbackHandler createClientCallbackHandler(String algorithm, String username, String passPhrase,
                                                        ResponseFormat responseFormat, int responseChoice,
                                                        boolean useNewPassPhrase, String newPassPhrase, byte[] newSeed,
                                                        String newOTP) throws Exception {
        OTPPasswordAndParameterCallbackHandler pwdAndParam =
                new OTPPasswordAndParameterCallbackHandler(passPhrase, responseFormat,
                        useNewPassPhrase, newSeed, newPassPhrase, newOTP);
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY
                                .useName(username)
                                .useExtendedChoiceCallback(responseChoice)
                                .usePartialCallbackHandler(pwdAndParam, ParameterCallback.class, PasswordCallback.class)
                                .allowSaslMechanisms(algorithm));


        return ClientUtils.getCallbackHandler(new URI("seems://irrelevant"), context);
    }

    private static class OTPPasswordAndParameterCallbackHandler implements CallbackHandler {
        private final ResponseFormat responseFormat;
        private final boolean useNewPassPhrase;
        private final String passPhrase;
        private final byte[] newSeed;
        private final String newPassPhrase;
        private final String newOTP;
        private boolean currentPasswordProvided;

        private OTPPasswordAndParameterCallbackHandler(String passPhrase, ResponseFormat responseFormat,
                                                       boolean useNewPassPhrase, byte[] newSeed, String newPassPhrase,
                                                       String newOTP) {
            this.responseFormat = responseFormat;
            this.useNewPassPhrase = useNewPassPhrase;
            this.passPhrase = passPhrase;
            this.newSeed = newSeed;
            this.newPassPhrase = newPassPhrase;
            this.newOTP = newOTP;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof ParameterCallback) {
                    ParameterCallback parameterCallback = (ParameterCallback) callback;
                    OneTimePasswordAlgorithmSpec spec = (OneTimePasswordAlgorithmSpec) parameterCallback.getParameterSpec();
                    if (currentPasswordProvided) {
                        // Set new password parameters
                        OneTimePasswordAlgorithmSpec newSpec = new OneTimePasswordAlgorithmSpec(spec.getAlgorithm(), newSeed, spec.getSequenceNumber());
                        parameterCallback.setParameterSpec(newSpec);
                    }
                } else if (callback instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback) callback;
                    if (passwordCallback.getPrompt().equals("Pass phrase")) {
                        if (responseFormat == ResponseFormat.PASSPHRASE) {
                            currentPasswordProvided = true;
                            passwordCallback.setPassword(passPhrase.toCharArray());
                        }
                    } else if (passwordCallback.getPrompt().equals("New pass phrase")) {
                        if (useNewPassPhrase) {
                            passwordCallback.setPassword(newPassPhrase.toCharArray());
                        }
                    } else if (passwordCallback.getPrompt().equals("One-time password")) {
                        if (responseFormat == ResponseFormat.MULTIWORD) {
                            currentPasswordProvided = true;
                            passwordCallback.setPassword(passPhrase.toCharArray());
                        }
                    } else if (passwordCallback.getPrompt().equals("New one-time password")) {
                        passwordCallback.setPassword(newOTP.toCharArray());
                    }
                }
            }
        }
    }
}
