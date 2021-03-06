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

package org.wildfly.security.password.impl;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.password.interfaces.BCryptPassword.*;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.*;
import static org.wildfly.security.password.interfaces.ClearPassword.*;
import static org.wildfly.security.password.interfaces.DigestPassword.*;
import static org.wildfly.security.password.interfaces.OneTimePassword.*;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.*;
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.*;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.*;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.*;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.*;
import static org.wildfly.security.password.interfaces.UnixMD5CryptPassword.*;
import static org.wildfly.security.password.interfaces.UnixDESCryptPassword.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactorySpi;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;

/**
 * The Elytron-provided password factory SPI implementation, which supports all the provided password types.
 */
public final class PasswordFactorySpiImpl extends PasswordFactorySpi {

    @Override
    protected Password engineGeneratePassword(final String algorithm, final KeySpec keySpec) throws InvalidKeySpecException {
        /*
         * When adding or removing an algorithm ensure that the registrations in 'WildFlyElytronPasswordProvider' are also
         * updated.
         */

        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                if (keySpec instanceof ClearPasswordSpec) {
                    return new ClearPasswordImpl(((ClearPasswordSpec) keySpec).getEncodedPassword().clone());
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    return new ClearPasswordImpl(((EncryptablePasswordSpec) keySpec).getPassword().clone());
                } else {
                    break;
                }
            }
            case ALGORITHM_BCRYPT: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new BCryptPasswordImpl((IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new BCryptPasswordImpl((SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new BCryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new BCryptPasswordImpl((EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_CRYPT_MD5: {
                if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new UnixMD5CryptPasswordImpl((SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new UnixMD5CryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new UnixMD5CryptPasswordImpl((EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_SUN_CRYPT_MD5:
            case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl(algorithm, (IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl(algorithm, (SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_CRYPT_SHA_256:
            case ALGORITHM_CRYPT_SHA_512: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl(algorithm, (IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl(algorithm, (SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_384:
            case ALGORITHM_DIGEST_SHA_512:
                if (keySpec instanceof DigestPasswordSpec) {
                    return new DigestPasswordImpl(algorithm, (DigestPasswordSpec) keySpec);
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    return new DigestPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                }
                break;
            case ALGORITHM_SIMPLE_DIGEST_MD2:
            case ALGORITHM_SIMPLE_DIGEST_MD5:
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:
            case ALGORITHM_SIMPLE_DIGEST_SHA_256:
            case ALGORITHM_SIMPLE_DIGEST_SHA_384:
            case ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                if (keySpec instanceof HashPasswordSpec) {
                    try {
                        return new SimpleDigestPasswordImpl(algorithm, (HashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new SimpleDigestPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new SimpleDigestPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512:
                if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new SaltedSimpleDigestPasswordImpl(algorithm, (SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new SaltedSimpleDigestPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new SaltedSimpleDigestPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                }
                break;
            case ALGORITHM_CRYPT_DES: {
                if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new UnixDESCryptPasswordImpl((SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new UnixDESCryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new UnixDESCryptPasswordImpl((EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | InvalidParameterSpecException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_BSD_CRYPT_DES: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new BSDUnixDESCryptPasswordImpl((IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new BSDUnixDESCryptPasswordImpl((SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new BSDUnixDESCryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new BSDUnixDESCryptPasswordImpl((EncryptablePasswordSpec) keySpec);
                    } catch (InvalidParameterSpecException | IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_SCRAM_SHA_1:
            case ALGORITHM_SCRAM_SHA_256:
            case ALGORITHM_SCRAM_SHA_384:
            case ALGORITHM_SCRAM_SHA_512: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new ScramDigestPasswordImpl(algorithm, (IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new ScramDigestPasswordImpl(algorithm, (SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new ScramDigestPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new ScramDigestPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                }
                else {
                    break;
                }
            }
            case ALGORITHM_OTP_MD5:
            case ALGORITHM_OTP_SHA1: {
                if (keySpec instanceof OneTimePasswordSpec) {
                    return new OneTimePasswordImpl(algorithm, (OneTimePasswordSpec) keySpec);
                }
                break;
            }
        }
        throw log.invalidKeySpecUnknownAlgorithmOrIncompatiblePasswordSpec();
    }

    @Override
    protected <S extends KeySpec> S engineGetKeySpec(final String algorithm, final Password password, final Class<S> keySpecType) throws InvalidKeySpecException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword.getKeySpec(keySpecType);
            }
        }
        throw new InvalidKeySpecException();
    }

    @Override
    protected boolean engineIsTranslatablePassword(final String algorithm, final Password password) {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return true;
            }
        }

        /*
         * When adding or removing an algorithm ensure that the registrations in 'WildFlyElytronPasswordProvider' are also
         * updated.
         */

        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                return (password instanceof ClearPassword);
            }
            case ALGORITHM_BCRYPT: {
                return (password instanceof BCryptPassword);
            }
            case ALGORITHM_CRYPT_MD5: {
                return (password instanceof UnixMD5CryptPassword);
            }
            case ALGORITHM_SUN_CRYPT_MD5:
            case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                return (password instanceof SunUnixMD5CryptPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_CRYPT_SHA_256:
            case ALGORITHM_CRYPT_SHA_512: {
                return (password instanceof UnixSHACryptPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_512:{
                return (password instanceof DigestPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_SIMPLE_DIGEST_MD2:
            case ALGORITHM_SIMPLE_DIGEST_MD5:
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:
            case ALGORITHM_SIMPLE_DIGEST_SHA_256:
            case ALGORITHM_SIMPLE_DIGEST_SHA_384:
            case ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                return (password instanceof SimpleDigestPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512: {
                return (password instanceof SaltedSimpleDigestPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_CRYPT_DES: {
                return (password instanceof UnixDESCryptPassword);
            }
            case ALGORITHM_BSD_CRYPT_DES: {
                return (password instanceof BSDUnixDESCryptPassword);
            }
            case ALGORITHM_SCRAM_SHA_1:
            case ALGORITHM_SCRAM_SHA_256: {
                return (password instanceof ScramDigestPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_OTP_MD5:
            case ALGORITHM_OTP_SHA1: {
                return (password instanceof OneTimePassword && algorithm.equals(password.getAlgorithm()));
            }
            default: {
                return false;
            }
        }
    }

    @Override
    protected Password engineTranslatePassword(final String algorithm, final Password password) throws InvalidKeyException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword;
            }
        }

        /*
         * When adding or removing an algorithm ensure that the registrations in 'WildFlyElytronPasswordProvider' are also
         * updated.
         */

        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                if (password instanceof ClearPasswordImpl) {
                    return password;
                } else if (password instanceof ClearPassword) {
                    return new ClearPasswordImpl((ClearPassword) password);
                }
                break;
            }
            case ALGORITHM_BCRYPT: {
                if (password instanceof BCryptPasswordImpl) {
                    return password;
                } else if (password instanceof BCryptPassword) {
                    return new BCryptPasswordImpl((BCryptPassword) password);
                }
                break;
            }
            case ALGORITHM_CRYPT_MD5: {
                if (password instanceof UnixMD5CryptPasswordImpl) {
                    return password;
                } else if (password instanceof UnixMD5CryptPassword) {
                    return new UnixMD5CryptPasswordImpl((UnixMD5CryptPassword) password);
                } else {
                    break;
                }
            }
            case ALGORITHM_SUN_CRYPT_MD5:
            case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                if (password instanceof SunUnixMD5CryptPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof SunUnixMD5CryptPassword && algorithm.equals(password.getAlgorithm())) {
                    return new SunUnixMD5CryptPasswordImpl((SunUnixMD5CryptPassword) password);
                } else {
                    break;
                }
            }
            case ALGORITHM_CRYPT_SHA_256:
            case ALGORITHM_CRYPT_SHA_512: {
                if (password instanceof UnixSHACryptPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof UnixSHACryptPassword  && algorithm.equals(password.getAlgorithm())) {
                    return new UnixSHACryptPasswordImpl((UnixSHACryptPassword) password);
                }
                break;
            }
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_512: {
                if (password instanceof DigestPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof DigestPassword  && algorithm.equals(password.getAlgorithm())) {
                    return new SimpleDigestPasswordImpl((SimpleDigestPassword) password);
                }
                break;
            }
            case ALGORITHM_SIMPLE_DIGEST_MD2:
            case ALGORITHM_SIMPLE_DIGEST_MD5:
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:
            case ALGORITHM_SIMPLE_DIGEST_SHA_256:
            case ALGORITHM_SIMPLE_DIGEST_SHA_384:
            case ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                if (password instanceof SimpleDigestPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof SimpleDigestPassword  && algorithm.equals(password.getAlgorithm())) {
                    return new SimpleDigestPasswordImpl((SimpleDigestPassword) password);
                }
                break;
            }
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512: {
                if (password instanceof SaltedSimpleDigestPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof SaltedSimpleDigestPassword && algorithm.equals(password.getAlgorithm())) {
                    return new SaltedSimpleDigestPasswordImpl((SaltedSimpleDigestPassword) password);
                }
                break;
            }
            case ALGORITHM_CRYPT_DES: {
                if (password instanceof UnixDESCryptPasswordImpl) {
                    return password;
                } else if (password instanceof UnixDESCryptPassword) {
                    return new UnixDESCryptPasswordImpl((UnixDESCryptPassword) password);
                }
                break;
            }
            case ALGORITHM_BSD_CRYPT_DES: {
                if (password instanceof BSDUnixDESCryptPasswordImpl) {
                    return password;
                } else if (password instanceof BSDUnixDESCryptPassword) {
                    return new BSDUnixDESCryptPasswordImpl((BSDUnixDESCryptPassword) password);
                }
                break;
            }
            case ALGORITHM_SCRAM_SHA_1:
            case ALGORITHM_SCRAM_SHA_256: {
                if (password instanceof ScramDigestPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof ScramDigestPassword && algorithm.equals(password.getAlgorithm())) {
                    return new ScramDigestPasswordImpl((ScramDigestPassword) password);
                }
                break;
            }
            case ALGORITHM_OTP_MD5:
            case ALGORITHM_OTP_SHA1: {
                if (password instanceof OneTimePasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof OneTimePassword && algorithm.equals(password.getAlgorithm())) {
                    return new OneTimePasswordImpl((OneTimePassword) password);
                }
                break;
            }
        }
        throw log.invalidKeyUnknownUnknownPasswordTypeOrAlgorithm();
    }

    @Override
    protected boolean engineVerify(final String algorithm, final Password password, final char[] guess) throws InvalidKeyException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword.verify(guess);
            }
        }
        throw new InvalidKeyException();
    }

    @Override
    protected <S extends KeySpec> boolean engineConvertibleToKeySpec(final String algorithm, final Password password, final Class<S> keySpecType) {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword.convertibleTo(keySpecType);
            }
        }
        return false;
    }
}
