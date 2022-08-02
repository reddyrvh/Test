package org.jose4j.lang;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

public class MathsTest
{
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Test(expected = ArithmeticException.class)
    public void addBad1()
    {
        long result = Maths.add(Long.MAX_VALUE, 1);
        log.debug("hrm... " + result);
    }

    @Test(expected = ArithmeticException.class)
    public void addBad2()
    {
        long result = Maths.add(1, Long.MAX_VALUE);
        log.debug("hrm... " + result);
    }

    @Test(expected = ArithmeticException.class)
    public void addBad3()
    {
        long result = Maths.add(0x7fffffffffff0fffL, Integer.MAX_VALUE);
        log.debug("hrm... " + result);
    }

    @Test
    public void addGood()
    {
        long result = Maths.add(256, 4);
        assertThat(result, equalTo(260L));

        result = Maths.add(-1, 1);
        assertThat(result, equalTo(0L));

        result = Maths.add(300, -120);
        assertThat(result, equalTo(180L));

        result = Maths.add(500, 123);
        assertThat(result, equalTo(623L));
    }

    @Test(expected = ArithmeticException.class)
    public void subtractBad1()
    {
        long result = Maths.subtract(-2L, Long.MAX_VALUE);
        log.debug("hrm... " + result);
    }

    @Test(expected = ArithmeticException.class)
    public void subtractBad2()
    {
        long result = Maths.subtract(-2, Long.MAX_VALUE);
        log.debug("hrm... " + result);
    }

    @Test(expected = ArithmeticException.class)
    public void subtractBad3()
    {
        long result = Maths.subtract(Long.MIN_VALUE, 72);
        log.debug("hrm... " + result);
    }

    @Test(expected = ArithmeticException.class)
    public void subtractBad4()
    {
        long result = Maths.subtract(0x8000000000000001L, 8);
        log.debug("hrm... " + result);
    }

    @Test(expected = ArithmeticException.class)
    public void subtractBad5()
    {
        long result = Maths.subtract(0x7fffffffffff6fffL, -54513);
        log.debug("hrm... " + result);
    }
}