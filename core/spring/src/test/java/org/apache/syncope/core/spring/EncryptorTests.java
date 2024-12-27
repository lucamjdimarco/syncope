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

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

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
    public static class EncryptorEncodeUnidimensionalTest {

        private final String value;
        private final CipherAlgorithm cipherAlgorithm;
        private final boolean validOrNullAlgorithm;
        private final boolean expectException;

        public EncryptorEncodeUnidimensionalTest(String value, CipherAlgorithm cipherAlgorithm, boolean validOrNullAlgorithm, boolean expectException) {
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
                    {null, null, true, true},
                    {"validString", null, false, true}
            });
        }

        @Test
        public void testEncode() {
            try {
                Encryptor encryptor = Encryptor.getInstance("secretKey");

                String encodedValue = encryptor.encode(value, cipherAlgorithm);

                if (expectException) {
                    fail("Expected exception, but method executed successfully.");
                } else {
                    assertNotNull("Encoded value should not be null for valid input.", encodedValue);
                    assertFalse("Encoded value should not be empty.", encodedValue.isEmpty());
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
}