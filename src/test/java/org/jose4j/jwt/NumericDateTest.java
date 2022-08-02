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

package org.jose4j.jwt;

import static org.junit.Assert.*;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public class NumericDateTest
{
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Test
    public void testComps1()
    {
        NumericDate one = NumericDate.fromSeconds(1350647028);
        NumericDate two = NumericDate.fromSeconds(1350647029);
        assertTrue(one.isBefore(two));
        assertFalse(two.isBefore(one));
        assertFalse(one.equals(two));
        assertFalse(one.isAfter(two));
        assertFalse(one.isOnOrAfter(two));
        assertTrue(two.isAfter(one));
        assertTrue(two.isOnOrAfter(one));
    }

    @Test
    public void testComps2()
    {
        NumericDate one = NumericDate.fromSeconds(1350647028);
        NumericDate two = NumericDate.fromSeconds(1350647028);
        assertFalse(one.isBefore(two));
        assertFalse(two.isBefore(one));
        assertTrue(one.isOnOrAfter(two));
        assertTrue(two.isOnOrAfter(one));
        assertFalse(one.isAfter(two));
        assertFalse(two.isAfter(one));
        assertTrue(one.equals(two));
    }

    @Test
    public void testEquals()
    {
        NumericDate date1 = NumericDate.now();
        NumericDate date2 = date1;
        assertTrue(date1.equals(date2));
        assertTrue(date2.equals(date1));
        date2 = NumericDate.fromSeconds(date1.getValue());
        assertTrue(date1.equals(date2));
        assertTrue(date2.equals(date1));
        date2.addSeconds(100);
        assertFalse(date1.equals(date2));
        assertFalse(date2.equals(date1));
        date1.addSeconds(100);
        assertTrue(date1.equals(date2));
        assertTrue(date2.equals(date1));
    }

    @Test
    public void testAddSecs()
    {
        NumericDate date = NumericDate.fromMilliseconds(0);
        int seconds = 100;
        date.addSeconds(seconds);
        assertEquals(100, date.getValue());

        date = NumericDate.fromMilliseconds(0);
        long secondsLong = 100L;
        date.addSeconds(secondsLong);
        assertEquals(100, date.getValue());

        date = NumericDate.fromMilliseconds(0);
        int secondsInt = 100;
        date.addSeconds(secondsInt);
        assertEquals(100, date.getValue());

        date = NumericDate.fromMilliseconds(0);
        date.addSeconds(100L);
        assertEquals(100, date.getValue());
    }

    @Test
    public void tooBigTooSmall()
    {
        expectOk(Long.MAX_VALUE);
        expectOk(Long.MAX_VALUE - Integer.MAX_VALUE);
        expectOk(Long.MAX_VALUE - Integer.MAX_VALUE * 100L);
        expectOk(Long.MAX_VALUE / 2);
        expectOk(Long.MAX_VALUE / 4);
        expectOk(Long.MAX_VALUE / 64);
        expectOk(Long.MAX_VALUE / 999);
        expectOk((Long.MAX_VALUE / 1000) + 1 );
        expectOk(Long.MAX_VALUE / 1000);
        expectOk((Long.MAX_VALUE / 1000) - 1 );

        expectOk(Long.MIN_VALUE);
        expectOk(Long.MIN_VALUE + Integer.MAX_VALUE);
        expectOk(Long.MIN_VALUE / 2);
        expectOk(Long.MIN_VALUE / 50);
        expectOk(Long.MIN_VALUE / 999);
        expectOk((Long.MIN_VALUE / 1000) - 1);
        expectOk(Long.MIN_VALUE / 1000);
        expectOk((Long.MIN_VALUE / 1000) + 1);

        exAdd(Long.MAX_VALUE, 1, false);
        exAdd(Long.MAX_VALUE, 60, false);
        exAdd(Long.MAX_VALUE, Integer.MAX_VALUE, false);
        exAdd(Long.MAX_VALUE, Long.MAX_VALUE, false);
        exAdd(Integer.MAX_VALUE, Long.MAX_VALUE, false);
        exAdd(60, Long.MAX_VALUE, false);
        exAdd(1, Long.MAX_VALUE, false);

        exAdd(Long.MAX_VALUE, 0, true);
        exAdd(Long.MAX_VALUE, -1, true);

        exAdd(Long.MIN_VALUE, -1, false);
        exAdd(Long.MIN_VALUE, -100, false);
        exAdd(Long.MIN_VALUE, Integer.MIN_VALUE, false);

        exAdd(Long.MIN_VALUE, 1, true);
        exAdd(Long.MIN_VALUE, 100, true);
        exAdd(Long.MIN_VALUE, Integer.MAX_VALUE, true);
        exAdd(Long.MIN_VALUE, Long.MAX_VALUE, true);
    }

    private void expectOk(long secs)
    {
        NumericDate numericDate = NumericDate.fromSeconds(secs);
        log.debug("ok " + numericDate);
    }

    private void exAdd(long secs, long toAdd, boolean expectOk)
    {
        NumericDate numericDate = NumericDate.fromSeconds(secs);

        try
        {
            numericDate.addSeconds(toAdd);
            if (!expectOk)
            {
                fail("NumericDate.fromSeconds(" + secs + ") add(" + toAdd + ") should have failed but now " + numericDate);
            }
        }
        catch (Exception e)
        {
            if (!expectOk)
            {
                log.debug("Expected: " + e);
            }
            else
            {
                throw e;
            }
        }
    }
}
