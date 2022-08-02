package org.jose4j.lang;

public class Maths
{
    //Two's complement -> if the leftmost bit is 0, the number is positive. Otherwise, it's negative.

    public static long add(long x, long y)
    {
        long result = x + y;
        // if both arguments have the opposite sign of the result
        if (0 > ((x ^ result) & (y ^ result)))
        {
            throw new ArithmeticException("long overflow adding: " + x + " + " + y + " = " + result);
        }
        return result;
    }

    public static long subtract(long x, long y)
    {
        long result = x - y;
        // when arguments have different signs and sign of result is different than the sign of x
        if (0 > ((x ^ y) & (x ^ result)))
        {
            throw new ArithmeticException("long overflow subtracting: " + x + " - " + y + " = " + result);
        }
        return result;
    }
}
