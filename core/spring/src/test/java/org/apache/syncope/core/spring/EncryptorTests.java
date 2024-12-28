/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.syncope.core.spring;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.security.Encryptor;

import org.jasypt.digest.StandardStringDigester;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.internal.matchers.Null;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.*;

@RunWith(Enclosed.class)
public class EncryptorTests {

    @RunWith(Parameterized.class)
    public static class GetInstanceTest {

        private final String secretKey;
        private final boolean expException;

        public GetInstanceTest(String secretKey, boolean expException) {
            this.secretKey = secretKey;
            this.expException = expException;
        }

        @Parameterized.Parameters(name = "Test case: secretKey={0}, isValid={1}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][]{
                    {"validKey", false},
                    {"anotherValidKey", false},
                    {"", false},
                    {null, false}
            });
        }

        @Test
        public void testGetInstance() {
            try {
                Encryptor encryptor = Encryptor.getInstance(secretKey);

                if (!expException) {
                    assertNotNull("Encryptor instance should not be null for valid keys.", encryptor);
                } else {
                    fail("Expected exception for invalid key, but method executed successfully.");
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid key: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid key.", true);
                }
            }
        }
    }

    @RunWith(Parameterized.class)
    public static class EncodeTest {

        private final String value;
        private final CipherAlgorithm cipherAlgorithm;
        private final boolean validOrNullAlgorithm;
        private final boolean expectException;

        public EncodeTest(String value, CipherAlgorithm cipherAlgorithm, boolean validOrNullAlgorithm, boolean expectException) {
            this.value = value;
            this.cipherAlgorithm = cipherAlgorithm;
            this.validOrNullAlgorithm = validOrNullAlgorithm;
            this.expectException = expectException;
        }

        @Parameterized.Parameters(name = "Test case: value={0}, cipherAlgorithm={1}, expectException={2}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][]{
                    {"validString", CipherAlgorithm.AES, true, false},
                    {"", CipherAlgorithm.AES, true, false},
                    {"validString", null, true, false},
                    {null, null, false, true},
                    //
                    //Jacoco
                    {"validString", CipherAlgorithm.BCRYPT, true, false},
                    {"validString", CipherAlgorithm.SHA256, true, false},
            });
        }

        @Test
        public void testEncode() {
            try {

                Encryptor encryptor = Encryptor.getInstance("secretKey");

                if(validOrNullAlgorithm) {
                    String encodedValue = encryptor.encode(value, cipherAlgorithm);

                    if (expectException) {
                        fail("Expected exception, but method executed successfully.");
                    } else {
                        assertNotNull("Encoded value should not be null for valid input.", encodedValue);
                        assertFalse("Encoded value should not be empty.", encodedValue.isEmpty());
                    }
                } else {
                    encryptor.encode("testString", CipherAlgorithm.valueOf("FAKE_ALGORITHM"));
                    fail("Expected IllegalArgumentException for unsupported algorithm");
                }

            } catch (IllegalArgumentException e){
                if (!expectException) {
                    fail("Did not expect an exception, but got: " + e.getMessage());
                } else {
                    assertTrue("Unexpected exception", expectException);
                }
            } catch (Exception e) {
                if (!expectException) {
                    fail("Did not expect an exception, but got: " + e.getMessage());
                } else {
                    assertTrue("Unexpected exception", expectException);
                }
            }
        }
    }

    @RunWith(Parameterized.class)
    public static class VerifyTest {

        private final String value;
        private final CipherAlgorithm cipherAlgorithm;
        private final boolean encodedValue;
        private final boolean isValidOrNull;
        private final boolean expectedResult;
        private final boolean expException;

        public VerifyTest(String value, CipherAlgorithm cipherAlgorithm, boolean encodedValue, boolean isValidOrNull, boolean expectedResult, boolean expException) {
            this.value = value;
            this.cipherAlgorithm = cipherAlgorithm;
            this.encodedValue = encodedValue;
            this.isValidOrNull = isValidOrNull;
            this.expectedResult = expectedResult;
            this.expException = expException;
        }

        @Parameterized.Parameters(name = "Test case: value={0}, cipherAlgorithm={1}, encodedValue={2}, isValidOrNull={3}, expectedResult={4}, expException={5}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][]{
                    //valid
                    {"validString", CipherAlgorithm.AES, true, true, true, false},
                    {"", CipherAlgorithm.AES, true, true, true, false},
                    {null, null, false, true, false, false},
                    {"validString", CipherAlgorithm.AES, false, true, false, false},
                    {"validString", null, true, false, false, true},
            });
        }

        @Test
        public void testVerify() {
            try {
                Encryptor encryptor = Encryptor.getInstance("defaultSecretKey");
                if(isValidOrNull && encodedValue) {
                    String encodedValue = encryptor.encode(value, cipherAlgorithm);
                    boolean result = encryptor.verify(value, cipherAlgorithm, encodedValue);
                    assertEquals("Expected and actual verification results do not match.", expectedResult, result);
                } else if(!isValidOrNull) {
                    String encodedValue = encryptor.encode("testString", CipherAlgorithm.valueOf("FAKE_ALGORITHM"));
                    boolean result = encryptor.verify(value, cipherAlgorithm, encodedValue);
                    fail("Expected IllegalArgumentException for unsupported algorithm");
                } else if(!encodedValue) {
                    boolean result = encryptor.verify(value, cipherAlgorithm, null);
                    assertFalse("Expected false verification result for null encoded value.", result);
                }

                if(expException) {
                    fail("Expected exception, but method executed successfully.");
                }


            } catch (NullPointerException e) {
                if (!expException) {
                    fail("Did not expect an exception, but got: " + e.getMessage());
                } else {
                    assertTrue("Unexpected exception", expException);
                }
            } catch (IllegalArgumentException e) {
                if (expException) {
                    Assert.assertTrue("Expected IllegalArgumentException for unsupported algorithm", expException);
                }
            }
            catch (Exception e) {
                if (expException) {
                    Assert.assertTrue("Expected exception", expException);
                }
            }
        }

    }

    @RunWith(Parameterized.class)
    public static class DecodeTests {

        private final String text;
        private final CipherAlgorithm cipherAlgorithm;
        private final boolean isValidOrNull;
        private final boolean expectException;

        public DecodeTests(String text, CipherAlgorithm cipherAlgorithm, boolean isValidOrNull, boolean expectException) {
            this.text = text;
            this.cipherAlgorithm = cipherAlgorithm;
            this.isValidOrNull = isValidOrNull;
            this.expectException = expectException;
        }

        @Parameterized.Parameters(name = "Test case: encoded={0}, cipherAlgorithm={1}, isValidOrNull={2} expectException={3}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][]{
                    {"validString", CipherAlgorithm.AES, true, false},
                    {"", CipherAlgorithm.AES, true, false},
                    {null, CipherAlgorithm.AES, true, false},
                    {"validString", null, true, false},
                    {"validString", null, false, true}
            });
        }

        @Test
        public void testDecode() {
            try {
                Encryptor encryptor = Encryptor.getInstance("aSecureRandomKey");

                String encoded = null;
                if (text != null && cipherAlgorithm != null) {
                    encoded = encryptor.encode(text, cipherAlgorithm);
                }

                if (isValidOrNull) {
                    String decoded = encryptor.decode(encoded, cipherAlgorithm);
                    if (expectException) {
                        fail("Expected exception, but method executed successfully.");
                    } else {
                        if(encoded == null || cipherAlgorithm == null) {
                            assertNull("Decoded value should be null for null input.", decoded);
                        } else {
                            assertNotNull("Decoded value should not be null for valid input.", decoded);
                            assertEquals("Decoded value should match the original input.", text, decoded);
                        }

                    }
                } else {
                    encryptor.decode("testString", CipherAlgorithm.valueOf("FAKE_ALGORITHM"));
                    fail("Expected IllegalArgumentException for unsupported algorithm");
                }

            } catch (IllegalArgumentException e) {
                if (!expectException) {
                    fail("Did not expect an IllegalArgumentException: " + e.getMessage());
                }
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException |
                     NoSuchPaddingException | InvalidKeyException |
                     IllegalBlockSizeException | BadPaddingException e) {
                if (!expectException) {
                    fail("Did not expect an exception: " + e.getMessage());
                }
            }
        }
    }

}