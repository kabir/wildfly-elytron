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

package org.wildfly.security.ssl;

final class OrCipherSuitePredicate extends CipherSuitePredicate {
    private final CipherSuitePredicate[] predicates;

    OrCipherSuitePredicate(final CipherSuitePredicate... predicates) {
        this.predicates = predicates;
    }

    boolean test(final MechanismDatabase.Entry entry) {
        for (CipherSuitePredicate predicate : predicates) {
            if (predicate != null && predicate.test(entry)) return true;
        }
        return false;
    }

    boolean isAlwaysTrue() {
        for (CipherSuitePredicate predicate : predicates) {
            if (predicate != null && predicate.isAlwaysTrue()) return true;
        }
        return false;
    }

    boolean isAlwaysFalse() {
        for (CipherSuitePredicate predicate : predicates) {
            if (predicate != null && ! predicate.isAlwaysFalse()) return false;
        }
        return true;
    }
}
