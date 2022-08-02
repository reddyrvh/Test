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
import org.junit.Test;

import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.BLOCK;
import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.*;
import static org.jose4j.jws.AlgorithmIdentifiers.*;

/**
 */
public class AlgorithmConstraintsTest
{
    @Test
    public void blockList1() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(BLOCK, "bad", "badder");
        constraints.checkConstraint("good");
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void blockList2() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(BLOCK, "bad", "badder");
        constraints.checkConstraint("bad");
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void blockList3() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(BLOCK, "bad", "badder");
        constraints.checkConstraint("badder");
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void blockListNone() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(BLOCK, NONE);
        constraints.checkConstraint(NONE);
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void permitList1() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(PERMIT, "good", "gooder", "goodest");
        constraints.checkConstraint("bad");
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void permitList2() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(PERMIT, "good", "gooder", "goodest");
        constraints.checkConstraint("also bad");
    }

    @Test
    public void permitList3() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(PERMIT, "good", "gooder", "goodest");
        constraints.checkConstraint("good");
        constraints.checkConstraint("gooder");
        constraints.checkConstraint("goodest");
    }

    @Test
    public void noRestrictions() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = AlgorithmConstraints.NO_CONSTRAINTS;

        String[] algs = {NONE, HMAC_SHA256, HMAC_SHA512, RSA_USING_SHA256, RSA_USING_SHA512,
                         ECDSA_USING_P256_CURVE_AND_SHA256, "something", A128KW, A256KW,
                         DIRECT, "etc,", "etc."};
        for (String alg : algs)
        {
            constraints.checkConstraint(alg);
        }
    }

}
