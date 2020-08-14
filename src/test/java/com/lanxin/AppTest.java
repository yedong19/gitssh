package com.lanxin;

import static org.junit.Assert.assertTrue;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.junit.Test;
import sun.security.provider.MD5;

/**
 * Unit test for simple App.
 */
public class AppTest {
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue() {
        Md5Hash hash=new Md5Hash("123","~!@#$%^&",10);
        System.out.println(hash.toString());
    }

}
