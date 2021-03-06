/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.sasl.scram;

import static java.util.Arrays.copyOfRange;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonMap;
import static org.wildfly.security._private.ElytronMessages.log;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
final class ScramSaslServer extends AbstractSaslServer {

    private static final int S_NO_MESSAGE = 1;
    private static final int S_FIRST_MESSAGE = 2;
    private static final int S_FINAL_MESSAGE = 3;

    private final boolean plus;
    private final MessageDigest messageDigest;
    private final Mac mac;
    private final SecureRandom secureRandom;
    private final int minimumIterationCount;
    private final int maximumIterationCount;
    private final String bindingType;
    private final byte[] bindingData;

    private String userName;
    private String authorizationID;
    private byte[] clientFirstMessage;
    private byte[] serverFirstMessage;
    private byte[] saltedPassword;
    private byte[] salt;
    private IteratedSaltedPasswordAlgorithmSpec algorithmSpec;
    private int iterationCount;
    private final boolean sendErrors = false;
    private int clientFirstMessageBareStart;
    private int cbindFlag;

    ScramSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final boolean plus, final Map<String, ?> props, final MessageDigest messageDigest, final Mac mac, final SecureRandom secureRandom, final String bindingType, final byte[] bindingData) {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.messageDigest = messageDigest;
        this.mac = mac;
        minimumIterationCount = getIntProperty(props, WildFlySasl.SCRAM_MIN_ITERATION_COUNT, 4096);
        maximumIterationCount = getIntProperty(props, WildFlySasl.SCRAM_MAX_ITERATION_COUNT, 32768);
        this.secureRandom = secureRandom;
        this.plus = plus;
        this.bindingType = bindingType;
        this.bindingData = bindingData;
    }

    public void init() {
        setNegotiationState(S_NO_MESSAGE);
    }

    public String getAuthorizationID() {
        return authorizationID;
    }

    protected byte[] evaluateMessage(final int state, final byte[] response) throws SaslException {
        boolean trace = log.isTraceEnabled();
        boolean ok = false;
        try {
            switch (state) {
                case S_NO_MESSAGE: {
                    if (response == null || response.length == 0) {
                        setNegotiationState(S_FIRST_MESSAGE);
                        // initial challenge
                        ok = true;
                        return NO_BYTES;
                    }
                    // fall through
                }
                case S_FIRST_MESSAGE: {
                    if (response == null || response.length == 0) {
                        throw log.saslClientRefusesToInitiateAuthentication(getMechanismName());
                    }
                    if(trace) log.tracef("[S] Client first message: %s%n", ByteIterator.ofBytes(response).hexEncode().drainToString());

                    final ByteStringBuilder b = new ByteStringBuilder();
                    int c;
                    ByteIterator bi = ByteIterator.ofBytes(response);
                    ByteIterator di = bi.delimitedBy(',');
                    CodePointIterator cpi = di.asUtf8String();

                    // == parse message ==

                    // binding type
                    cbindFlag = bi.next();
                    if (cbindFlag == 'p' && plus) {
                        assert bindingType != null; // because {@code plus} is true
                        assert bindingData != null;
                        if (bi.next() != '=') {
                            throw log.saslInvalidClientMessage(getMechanismName());
                        }
                        if (! bindingType.equals(cpi.drainToString())) {
                            // nope, auth must fail because we cannot acquire the same binding
                            throw log.saslChannelBindingTypeMismatch(getMechanismName());
                        }
                        bi.next(); // skip delimiter
                    } else if ((cbindFlag == 'y' || cbindFlag == 'n') && !plus) {
                        if (bi.next() != ',') {
                            throw log.saslInvalidClientMessage(getMechanismName());
                        }
                    } else {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }

                    // authorization ID
                    c = bi.next();
                    if (c == 'a') {
                        if (bi.next() != '=') {
                            throw log.saslInvalidClientMessage(getMechanismName());
                        }
                        authorizationID = cpi.drainToString();
                        bi.next(); // skip delimiter
                    } else if (c != ',') {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }

                    clientFirstMessageBareStart = bi.offset();

                    // user name
                    if (bi.next() == 'n') {
                        if (bi.next() != '=') {
                            throw log.saslInvalidClientMessage(getMechanismName());
                        }
                        ByteStringBuilder bsb = new ByteStringBuilder();
                        StringPrep.encode(cpi.drainToString(), bsb, StringPrep.PROFILE_SASL_QUERY | StringPrep.UNMAP_SCRAM_LOGIN_CHARS);
                        userName = new String(bsb.toArray(), StandardCharsets.UTF_8);
                        bi.next(); // skip delimiter
                    } else {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }

                    // random nonce
                    if (bi.next() != 'r' || bi.next() != '=') {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }
                    byte[] nonce = di.drain();
                    if(trace) log.tracef("[S] Client nonce: %s%n", ByteIterator.ofBytes(nonce).hexEncode().drainToString());

                    if (bi.hasNext()) {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }

                    clientFirstMessage = response;

                    // == send first challenge ==

                    // get salted password
                    final NameCallback nameCallback = new NameCallback("Remote authentication name", userName);
                    saltedPassword = null;
                    getPredigestedSaltedPassword(nameCallback);
                    if (saltedPassword == null) {
                        getSaltedPasswordFromTwoWay(nameCallback, b);
                    }
                    if (saltedPassword == null) {
                        getSaltedPasswordFromPasswordCallback(nameCallback, b);
                    }
                    if (saltedPassword == null) {
                        throw log.saslCallbackHandlerDoesNotSupportCredentialAcquisition(getMechanismName(), null);
                    }
                    if(trace) log.tracef("[S] Salt: %s%n", ByteIterator.ofBytes(salt).hexEncode().drainToString());
                    if(trace) log.tracef("[S] Salted password: %s%n", ByteIterator.ofBytes(saltedPassword).hexEncode().drainToString());

                    // nonce (client + server nonce)
                    b.append('r').append('=');
                    b.append(nonce);
                    b.append(ScramUtil.generateNonce(28, getRandom()));
                    b.append(',');

                    // salt
                    b.append('s').append('=');
                    b.appendLatin1(ByteIterator.ofBytes(salt).base64Encode());
                    b.append(',');
                    b.append('i').append('=');
                    b.append(Integer.toString(iterationCount));

                    setNegotiationState(S_FINAL_MESSAGE);
                    ok = true;
                    return serverFirstMessage = b.toArray();
                }
                case S_FINAL_MESSAGE: {
                    final ByteStringBuilder b = new ByteStringBuilder();

                    ByteIterator bi = ByteIterator.ofBytes(response);
                    ByteIterator di = bi.delimitedBy(',');

                    // == parse message ==

                    // first comes the channel binding
                    if (bi.next() != 'c' || bi.next() != '=') {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }

                    final ByteIterator bindingIterator = di.base64Decode();

                    // -- sub-parse of binding data --
                    if(bindingIterator.next() != cbindFlag) {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }
                    switch (cbindFlag) {
                        case 'n': case 'y': { // n,[a=authzid],
                            if (plus) throw log.saslChannelBindingNotProvided(getMechanismName());

                            parseAuthorizationId(bindingIterator);

                            if (bindingIterator.hasNext()) { // require end
                                throw log.saslInvalidClientMessage(getMechanismName());
                            }
                            break;
                        }
                        case 'p': { // p=bindingType,[a=authzid],bindingData
                            if (! plus) {
                                throw log.saslChannelBindingNotSupported(getMechanismName());
                            }
                            if (bindingIterator.next() != '=') {
                                throw log.saslInvalidClientMessage(getMechanismName());
                            }
                            if (! bindingType.equals(bindingIterator.delimitedBy(',').asUtf8String().drainToString())) {
                                throw log.saslChannelBindingTypeMismatch(getMechanismName());
                            }
                            parseAuthorizationId(bindingIterator);

                            // following is the raw channel binding data
                            if (! bindingIterator.contentEquals(ByteIterator.ofBytes(bindingData))) {
                                throw log.saslChannelBindingTypeMismatch(getMechanismName());
                            }
                            if (bindingIterator.hasNext()) { // require end
                                throw log.saslInvalidClientMessage(getMechanismName());
                            }
                            break;
                        }
                    }
                    bi.next(); // skip delimiter

                    // nonce
                    if (bi.next() != 'r' || bi.next() != '=') {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }
                    while (di.hasNext()) { di.next(); }

                    // proof
                    final int proofOffset = bi.offset();
                    bi.next(); // skip delimiter
                    if (bi.next() != 'p' || bi.next() != '=') {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }
                    byte[] recoveredClientProofEncoded = di.drain();
                    if (bi.hasNext()) {
                        throw log.saslInvalidClientMessage(getMechanismName());
                    }

                    // == verify proof ==

                    // client key
                    byte[] clientKey;
                    mac.reset();
                    mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                    mac.update(Scram.CLIENT_KEY_BYTES);
                    clientKey = mac.doFinal();
                    if(trace) log.tracef("[S] Client key: %s%n", ByteIterator.ofBytes(clientKey).hexEncode().drainToString());

                    // stored key
                    byte[] storedKey;
                    messageDigest.reset();
                    messageDigest.update(clientKey);
                    storedKey = messageDigest.digest();
                    if(trace) log.tracef("[S] Stored key: %s%n", ByteIterator.ofBytes(storedKey).hexEncode().drainToString());

                    // client signature
                    mac.reset();
                    mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
                    mac.update(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length - clientFirstMessageBareStart);
                    if(trace) log.tracef("[S] Using client first message: %s%n", ByteIterator.ofBytes(copyOfRange(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length)).hexEncode().drainToString());
                    mac.update((byte) ',');
                    mac.update(serverFirstMessage);
                    if(trace) log.tracef("[S] Using server first message: %s%n", ByteIterator.ofBytes(serverFirstMessage).hexEncode().drainToString());
                    mac.update((byte) ',');
                    mac.update(response, 0, proofOffset); // client-final-message-without-proof
                    if(trace) log.tracef("[S] Using client final message without proof: %s%n", ByteIterator.ofBytes(copyOfRange(response, 0, proofOffset)).hexEncode().drainToString());
                    byte[] clientSignature = mac.doFinal();
                    if(trace) log.tracef("[S] Client signature: %s%n", ByteIterator.ofBytes(clientSignature).hexEncode().drainToString());

                    // server key
                    byte[] serverKey;
                    mac.reset();
                    mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                    mac.update(Scram.SERVER_KEY_BYTES);
                    serverKey = mac.doFinal();
                    if(trace) log.tracef("[S] Server key: %s%n", ByteIterator.ofBytes(serverKey).hexEncode().drainToString());

                    // server signature
                    byte[] serverSignature;
                    mac.reset();
                    mac.init(new SecretKeySpec(serverKey, mac.getAlgorithm()));
                    mac.update(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length - clientFirstMessageBareStart);
                    mac.update((byte) ',');
                    mac.update(serverFirstMessage);
                    mac.update((byte) ',');
                    mac.update(response, 0, proofOffset); // client-final-message-without-proof
                    serverSignature = mac.doFinal();
                    if(trace) log.tracef("[S] Server signature: %s%n", ByteIterator.ofBytes(serverSignature).hexEncode().drainToString());

                    if(trace) log.tracef("[S] Client proof string: %s%n", CodePointIterator.ofUtf8Bytes(recoveredClientProofEncoded).drainToString());
                    b.setLength(0);
                    byte[] recoveredClientProof = ByteIterator.ofBytes(recoveredClientProofEncoded).base64Decode().drain();
                    if(trace) log.tracef("[S] Client proof: %s%n", ByteIterator.ofBytes(recoveredClientProof).hexEncode().drainToString());

                    // now check the proof
                    byte[] recoveredClientKey = clientSignature.clone();
                    ScramUtil.xor(recoveredClientKey, recoveredClientProof);
                    if(trace) log.tracef("[S] Recovered client key: %s%n", ByteIterator.ofBytes(recoveredClientKey).hexEncode().drainToString());
                    if (! Arrays.equals(recoveredClientKey, clientKey)) {
                        // bad auth, send error
                        if (sendErrors) {
                            b.setLength(0);
                            b.append("e=invalid-proof");
                            setNegotiationState(FAILED_STATE);
                            return b.toArray();
                        }
                        throw log.saslAuthenticationRejectedInvalidProof(getMechanismName());
                    }

                    if (authorizationID == null) {
                        authorizationID = userName;
                    }else{
                        ByteStringBuilder bsb = new ByteStringBuilder();
                        StringPrep.encode(authorizationID, bsb, StringPrep.PROFILE_SASL_QUERY | StringPrep.UNMAP_SCRAM_LOGIN_CHARS);
                        authorizationID = new String(bsb.toArray(), StandardCharsets.UTF_8);
                    }
                    final AuthorizeCallback authorizeCallback = new AuthorizeCallback(userName, authorizationID);
                    try {
                        tryHandleCallbacks(authorizeCallback);
                    } catch (UnsupportedCallbackException e) {
                        throw log.saslAuthorizationUnsupported(getMechanismName(), e);
                    }
                    if ( ! authorizeCallback.isAuthorized()) {
                        throw log.saslAuthorizationFailed(getMechanismName(), userName, authorizationID);
                    }

                    // == send response ==
                    b.setLength(0);
                    b.append('v').append('=');
                    b.appendUtf8(ByteIterator.ofBytes(serverSignature).base64Encode());

                    setNegotiationState(COMPLETE_STATE);
                    ok = true;
                    return b.toArray();
                }
                case COMPLETE_STATE: {
                    if (response != null && response.length != 0) {
                        throw log.saslClientSentExtraMessage(getMechanismName());
                    }
                    ok = true;
                    return null;
                }
                case FAILED_STATE: {
                    throw log.saslAuthenticationFailed(getMechanismName());
                }
            }
            throw Assert.impossibleSwitchCase(state);
        } catch (ArrayIndexOutOfBoundsException | InvalidKeyException ignored) {
            throw log.saslInvalidClientMessage(getMechanismName());
        } finally {
            if (! ok) {
                setNegotiationState(FAILED_STATE);
            }
        }
    }

    private void parseAuthorizationId(ByteIterator bindingIterator) throws SaslException {
        if (bindingIterator.next() != ',') {
            throw log.saslInvalidClientMessage(getMechanismName());
        }
        switch (bindingIterator.next()) {
            case ',':
                if (authorizationID != null) {
                    throw log.saslInvalidClientMessage(getMechanismName());
                }
                break;
            case 'a': {
                if (bindingIterator.next() != '=') {
                    throw log.saslInvalidClientMessage(getMechanismName());
                }
                if (! bindingIterator.delimitedBy(',').asUtf8String().drainToString().equals(authorizationID)) {
                    throw log.saslInvalidClientMessage(getMechanismName());
                }
                if (bindingIterator.next() != ',') {
                    throw log.saslInvalidClientMessage(getMechanismName());
                }
                break;
            }
            default: throw log.saslInvalidClientMessage(getMechanismName());
        }
    }

    private void getPredigestedSaltedPassword(NameCallback nameCallback) throws SaslException {
        String passwordType;
        switch (getMechanismName()) {
            case SaslMechanismInformation.Names.SCRAM_SHA_1:
            case SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS: {
                passwordType = ScramDigestPassword.ALGORITHM_SCRAM_SHA_1;
                break;
            }
            case SaslMechanismInformation.Names.SCRAM_SHA_256:
            case SaslMechanismInformation.Names.SCRAM_SHA_256_PLUS: {
                passwordType = ScramDigestPassword.ALGORITHM_SCRAM_SHA_256;
                break;
            }
            case SaslMechanismInformation.Names.SCRAM_SHA_384:
            case SaslMechanismInformation.Names.SCRAM_SHA_384_PLUS: {
                passwordType = ScramDigestPassword.ALGORITHM_SCRAM_SHA_384;
                break;
            }
            case SaslMechanismInformation.Names.SCRAM_SHA_512:
            case SaslMechanismInformation.Names.SCRAM_SHA_512_PLUS: {
                passwordType = ScramDigestPassword.ALGORITHM_SCRAM_SHA_512;
                break;
            }
            default: throw Assert.impossibleSwitchCase(getMechanismName());
        }
        CredentialCallback credentialCallback = new CredentialCallback(singletonMap(ScramDigestPassword.class, singleton(passwordType)));
        try {
            tryHandleCallbacks(nameCallback, credentialCallback);
        } catch (UnsupportedCallbackException e) {
            final Callback callback = e.getCallback();
            if (callback == nameCallback) {
                throw log.saslCallbackHandlerDoesNotSupportUserName(getMechanismName(), e);
            } else if (callback == credentialCallback) {
                return; // pre digested not supported
            } else {
                throw log.saslCallbackHandlerFailedForUnknownReason(getMechanismName(), e);
            }
        }
        Password password = (Password) credentialCallback.getCredential();
        if (password instanceof ScramDigestPassword) {
            // got a scram password
            final ScramDigestPassword scramDigestPassword = (ScramDigestPassword) password;
            if (! passwordType.equals(scramDigestPassword.getAlgorithm())) {
                return;
            }
            iterationCount = scramDigestPassword.getIterationCount();
            salt = scramDigestPassword.getSalt();
            if (iterationCount < minimumIterationCount) {
                throw log.saslIterationCountIsTooLow(getMechanismName(), iterationCount, minimumIterationCount);
            } else if (iterationCount > maximumIterationCount) {
                throw log.saslIterationCountIsTooHigh(getMechanismName(), iterationCount, maximumIterationCount);
            }
            if (salt == null) {
                throw log.saslSaltMustBeSpecified(getMechanismName());
            }
            saltedPassword = scramDigestPassword.getDigest();
        }
    }

    private void getSaltedPasswordFromTwoWay(NameCallback nameCallback, ByteStringBuilder b) throws SaslException {
        CredentialCallback credentialCallback = new CredentialCallback(singletonMap(TwoWayPassword.class, emptySet()));
        final ParameterCallback parameterCallback = new ParameterCallback(IteratedSaltedPasswordAlgorithmSpec.class);
        try {
            tryHandleCallbacks(nameCallback, parameterCallback, credentialCallback);
            algorithmSpec = (IteratedSaltedPasswordAlgorithmSpec) parameterCallback.getParameterSpec();
            if (algorithmSpec == null) throw new FastUnsupportedCallbackException(parameterCallback);
        } catch (UnsupportedCallbackException e) {
            Callback callback = e.getCallback();
            if (callback == nameCallback) {
                throw log.saslCallbackHandlerDoesNotSupportUserName(getMechanismName(), e);
            } else if (callback == credentialCallback) {
                return; // credential acquisition not supported
            } else if (callback == parameterCallback) {
                // one more try, with default parameters
                salt = ScramUtil.generateSalt(16, getRandom());
                algorithmSpec = new IteratedSaltedPasswordAlgorithmSpec(minimumIterationCount, salt);
                try {
                    tryHandleCallbacks(nameCallback, credentialCallback);
                } catch (UnsupportedCallbackException ex) {
                    callback = ex.getCallback();
                    if (callback == nameCallback) {
                        throw log.saslCallbackHandlerDoesNotSupportUserName(getMechanismName(), ex);
                    } else if (callback == credentialCallback) {
                        return;
                    } else {
                        throw log.saslCallbackHandlerFailedForUnknownReason(getMechanismName(), ex);
                    }
                }
            } else {
                throw log.saslCallbackHandlerDoesNotSupportCredentialAcquisition(getMechanismName(), e);
            }
        }

        // get the clear password
        TwoWayPassword password = (TwoWayPassword) credentialCallback.getCredential();
        char[] passwordChars = ScramUtil.getTwoWayPasswordChars(getMechanismName(), password);
        getSaltedPasswordFromPasswordChars(passwordChars, b);
    }

    private void getSaltedPasswordFromPasswordCallback(NameCallback nameCallback, ByteStringBuilder b) throws SaslException {
        final PasswordCallback passwordCallback = new PasswordCallback("User password", false);
        try {
            tryHandleCallbacks(nameCallback, passwordCallback);
        } catch (UnsupportedCallbackException e) {
            final Callback callback = e.getCallback();
            if (callback == nameCallback) {
                throw log.saslCallbackHandlerDoesNotSupportUserName(getMechanismName(), e);
            } else if (callback == passwordCallback) {
                return; // PasswordCallback not supported
            } else {
                throw log.saslCallbackHandlerFailedForUnknownReason(getMechanismName(), e);
            }
        }

        salt = ScramUtil.generateSalt(16, getRandom());
        algorithmSpec = new IteratedSaltedPasswordAlgorithmSpec(minimumIterationCount, salt);

        char[] passwordChars = passwordCallback.getPassword();
        passwordCallback.clearPassword();
        getSaltedPasswordFromPasswordChars(passwordChars, b);
    }

    private void getSaltedPasswordFromPasswordChars(char[] passwordChars, ByteStringBuilder b) throws SaslException {
        StringPrep.encode(passwordChars, b, StringPrep.PROFILE_SASL_STORED);
        Arrays.fill(passwordChars, (char)0); // wipe out the password
        passwordChars = new String(b.toArray(), StandardCharsets.UTF_8).toCharArray();
        b.setLength(0);

        iterationCount = algorithmSpec.getIterationCount();
        salt = algorithmSpec.getSalt();
        if (iterationCount < minimumIterationCount) {
            throw log.saslIterationCountIsTooLow(getMechanismName(), iterationCount, minimumIterationCount);
        } else if (iterationCount > maximumIterationCount) {
            throw log.saslIterationCountIsTooHigh(getMechanismName(), iterationCount, maximumIterationCount);
        }
        if (salt == null) {
            throw log.saslSaltMustBeSpecified(getMechanismName());
        }
        try {
            saltedPassword = ScramUtil.calculateHi(mac, passwordChars, salt, 0, salt.length, iterationCount);
            Arrays.fill(passwordChars, (char)0); // wipe out the password
        } catch (InvalidKeyException e) {
            throw log.saslInvalidMacInitializationKey(getMechanismName());
        }
    }

    private Random getRandom() {
        return secureRandom != null ? secureRandom : ThreadLocalRandom.current();
    }

    public void dispose() throws SaslException {
        clientFirstMessage = null;
        serverFirstMessage = null;
        saltedPassword = null;
        setNegotiationState(FAILED_STATE);
        mac.reset();
        messageDigest.reset();
    }
}
