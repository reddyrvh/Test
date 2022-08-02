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

package org.jose4j.lang;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 */
public class ByteUtilTest
{
    private static final Logger log = LoggerFactory.getLogger(ByteUtil.class);

    @Test
    public void testLeftRight()
    {
        byte[] fullCekBytes = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] hmacKeyBytes = new byte[fullCekBytes.length/2];
        byte[] encKeyBytes = new byte[fullCekBytes.length/2];
        System.arraycopy(fullCekBytes, 0, hmacKeyBytes, 0, hmacKeyBytes.length);
        System.arraycopy(fullCekBytes, hmacKeyBytes.length, encKeyBytes, 0, encKeyBytes.length);

        byte[] left = ByteUtil.leftHalf(fullCekBytes);
        byte[] right = ByteUtil.rightHalf(fullCekBytes);
        Assert.assertTrue(Arrays.equals(hmacKeyBytes, left));
        Assert.assertTrue(Arrays.equals(encKeyBytes, right));
    }

    @Test
    public void testGetBytesLong()
    {
        // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-13#appendix-B.3
        long value = 408;
        byte[] bytes = ByteUtil.getBytes(value);
        int[] integers = ByteUtil.convertSignedTwosCompToUnsigned(bytes);
        Assert.assertEquals(8, integers.length);
        for (int i = 0 ; i < 6 ; i++)
        {
            Assert.assertEquals(0, integers[i]);
        }

        Assert.assertEquals(1, integers[6]);
        Assert.assertEquals(152, integers[7]);
    }

    @Test
    public void testConcat1()
    {
        byte[] first = new byte[2];
        byte[] second = new byte[10];
        byte[] third = new byte[15];

        byte[] result = ByteUtil.concat(first, second, third);

        Assert.assertEquals(first.length + second.length + third.length, result.length);

        Assert.assertTrue(Arrays.equals(new byte[result.length], result));
    }

    @Test
    public void testConcat2()
    {
        byte[] first = new byte[] {1, 2, 7};
        byte[] second = new byte[] {38, 101};
        byte[] third = new byte[] {5 , 6, 7};

        byte[] result = ByteUtil.concat(first, second, third);

        Assert.assertEquals(first.length + second.length + third.length, result.length);

        Assert.assertTrue(Arrays.equals(new byte[] {1, 2, 7, 38, 101, 5, 6, 7} , result));
    }

    @Test
    public void testConcat3()
    {
        byte[] first = new byte[] {1, 2, 7};
        byte[] second = new byte[] {};
        byte[] third = new byte[] {5 , 6, 7};
        byte[] fourth = new byte[] {};

        byte[] result = ByteUtil.concat(first, second, third);

        Assert.assertEquals(first.length + second.length + third.length + fourth.length, result.length);

        Assert.assertTrue(Arrays.equals(new byte[] {1, 2, 7, 5, 6, 7} , result));
    }

    @Test
    public void testGetBytesOne()
    {
        byte[] bytes = ByteUtil.getBytes(1);
        Assert.assertEquals(4, bytes.length);
        Assert.assertEquals(0, bytes[0]);
        Assert.assertEquals(0, bytes[1]);
        Assert.assertEquals(0, bytes[2]);
        Assert.assertEquals(1, bytes[3]);
    }

    @Test
    public void testGetBytesTwo()
    {
        byte[] bytes = ByteUtil.getBytes(2);
        Assert.assertEquals(4, bytes.length);
        Assert.assertEquals(0, bytes[0]);
        Assert.assertEquals(0, bytes[1]);
        Assert.assertEquals(0, bytes[2]);
        Assert.assertEquals(2, bytes[3]);
    }

    @Test
    public void testGetBytesMax()
    {
        byte[] bytes = ByteUtil.getBytes(Integer.MAX_VALUE);
        Assert.assertEquals(4, bytes.length);
    }

    @Test
    public void testConvert() throws JoseException
    {
        for (int i = 0; i < 256; i++)
        {
            byte b = ByteUtil.getByte(i);
            int anInt = ByteUtil.getInt(b);
            Assert.assertEquals(i, anInt);
        }
    }

    @Test
    public void testConvert2() throws JoseException
    {
        boolean keepGoing = true;
        for (byte b = Byte.MIN_VALUE; keepGoing; b++)
        {
            int i = ByteUtil.getInt(b);
            byte aByte = ByteUtil.getByte(i);
            Assert.assertEquals(b, aByte);
            if (b == Byte.MAX_VALUE)
            {
                keepGoing = false;
            }
        }
    }

    @Test
    public void testEquals0()
    {
        byte[] bytes1 = ByteUtil.randomBytes(32);
        byte[] bytes2 = new byte[bytes1.length];
        bytes1[0] = 1;
        compareTest(bytes1, bytes2, false);
        System.arraycopy(bytes1, 0, bytes2, 0, bytes1.length);
        compareTest(bytes1, bytes2, true);
    }

    @Test
    public void testRandomBytesNullSecRan()
    {
        byte[] bytes = ByteUtil.randomBytes(4, null);
        Assert.assertTrue(bytes.length == 4);
    }

    @Test
    public void testEquals1()
    {
        compareTest(new byte[]{-1}, new byte[]{1}, false);
    }

    @Test
    public void testEquals2()
    {
        compareTest("good", "good", true);
    }

    @Test
    public void testEquals3()
    {
        compareTest("baad", "good", false);
    }

    @Test
    public void testEquals3b()
    {
        compareTest("bad", "good", false);
    }

    @Test
    public void testEquals4()
    {
        compareTest("", "niner", false);
    }

    @Test
    public void testEquals5()
    {
        compareTest("foo", "bar", false);
    }

    @Test
    public void testEquals6()
    {
        compareTest(new byte[]{-1, 123, 7, 1}, new byte[]{-1, 123, 7, 1}, true);
    }

    @Test
    public void testEquals7()
    {
        compareTest(new byte[]{-1, 123, -19, 1}, new byte[]{-1, 123, 7, 1}, false);
    }

    @Test
    public void testEquals8()
    {
        compareTest(new byte[]{-1, 123, 7, 1, -32}, new byte[]{-1, 123, 7, 1}, false);
    }

    @Test
    public void testEquals9()
    {
        compareTest(new byte[]{-1, 123, 7, 1}, new byte[]{-1, 123, 7, 1, 0}, false);
    }

    @Test
    public void testEquals10()
    {
        compareTest(null, new byte[]{-1, 123, 7, 1, 0}, false);
    }

    @Test
    public void testEquals11()
    {
        compareTest(new byte[]{-1, 123, 7, 1}, null, false);
    }

    @Test
    public void testEquals12()
    {
        compareTest(new byte[0], new byte[]{-1, 123, 7, 1, 0}, false);
    }

    @Test
    public void testEquals13()
    {
        compareTest(new byte[]{-1, 123, 7, 1}, new byte[0], false);
    }

    @Test
    public void testEquals14()
    {
        compareTest(new byte[0], new byte[0], true);
    }

    @Test
    public void testEquals15()
    {
        compareTest((byte [])null, null, true); 
    }

    private void compareTest(String first, String second, boolean shouldMatch)
    {
        compareTest(StringUtil.getBytesUtf8(first), StringUtil.getBytesUtf8(second), shouldMatch);
    }

    private void compareTest(byte[] first, byte[] second, boolean shouldMatch)
    {
        Assert.assertEquals(shouldMatch, ByteUtil.secureEquals(first,second));
    }

    @Test
    public void bitLengthsLegit()
    {
        Assert.assertEquals(0, ByteUtil.bitLength(0));
        Assert.assertEquals(8, ByteUtil.bitLength(1));
        Assert.assertEquals(128, ByteUtil.bitLength(16));
        Assert.assertEquals(256, ByteUtil.bitLength(32));
        Assert.assertEquals(512, ByteUtil.bitLength(64));
        Assert.assertEquals(1024, ByteUtil.bitLength(128));
        Assert.assertEquals(2147483640, ByteUtil.bitLength(268435455)); // the max
    }

    @Test
    public void bitLengthsNotLegit()
    {
        bitLengthNotLegit(Integer.MAX_VALUE);
        bitLengthNotLegit(Integer.MIN_VALUE);
        bitLengthNotLegit(268435456);
        bitLengthNotLegit(536870929);
        bitLengthNotLegit(536870920);
        bitLengthNotLegit(536870928);
        bitLengthNotLegit(-1);
        bitLengthNotLegit(-536870928);
    }

    public void bitLengthNotLegit(int byteLength)
    {
        try
        {
            int bitLength = ByteUtil.bitLength(byteLength);
            Assert.fail("should not have gotten bit length "+bitLength+" from byte length " + byteLength);
        }
        catch (Exception e)
        {
            log.debug("This was expected: " + e);
        }
    }
}
