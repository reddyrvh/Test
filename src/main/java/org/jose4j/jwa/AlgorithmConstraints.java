/*
 * Copyright 2012-2017 Brian Campbell
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
package org.jose4j.jwa;

import org.jose4j.lang.InvalidAlgorithmException;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.BLOCK;
import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT;
import static org.jose4j.jws.AlgorithmIdentifiers.NONE;

/**
 */
public class AlgorithmConstraints
{
    public static final AlgorithmConstraints NO_CONSTRAINTS = new AlgorithmConstraints(ConstraintType.BLOCK);
    public static final AlgorithmConstraints DISALLOW_NONE = new AlgorithmConstraints(BLOCK, NONE);
    public static final AlgorithmConstraints ALLOW_ONLY_NONE = new AlgorithmConstraints(PERMIT, NONE);

    public enum ConstraintType {
        /**
         *  @deprecated in favor of more inclusive terminology. Use {@link #PERMIT} instead.
         */
        @Deprecated WHITELIST,

        /**
         * @deprecated in favor of more inclusive terminology. Use {@link #BLOCK} instead.
         */
        @Deprecated BLACKLIST,

        /**
         * Allow only the indicated algorithms and no others.
         * @since 0.7.2
         */
        PERMIT,

        /**
         * Block the indicated algorithms while allowing all others that are defined and supported.
         * @since 0.7.2
         */
        BLOCK}

    private final ConstraintType type;
    private final Set<String> algorithms;

    public AlgorithmConstraints(ConstraintType type, String... algorithms)
    {
        if (type == null)
        {
            throw new NullPointerException("ConstraintType cannot be null");
        }
        this.type = type;
        this.algorithms = new HashSet<>(Arrays.asList(algorithms));
    }

    public void checkConstraint(String algorithm) throws InvalidAlgorithmException
    {
        switch (type)
        {
            case PERMIT:
            case WHITELIST:
                if (!algorithms.contains(algorithm))
                {
                    throw new InvalidAlgorithmException("'" +algorithm + "' is not a permitted algorithm.");
                }
                break;
            case BLOCK:
            case BLACKLIST:
                if (algorithms.contains(algorithm))
                {
                    throw new InvalidAlgorithmException("'" + algorithm + "' is a blocked algorithm.");
                }
                break;
        }
    }
}
