package org.apache.syncope.core.spring;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.common.lib.policy.PasswordRuleConf;
import org.apache.syncope.core.spring.policy.DefaultPasswordRule;
import org.apache.syncope.core.spring.policy.PasswordPolicyException;
import org.passay.IllegalCharacterRule;
import org.passay.LengthRule;
import org.passay.Rule;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.syncope.core.spring.utils.ConcreteUser;

import static org.junit.Assert.*;


@RunWith(Enclosed.class)
public class DefaultPasswordRuleTests {

    @RunWith(Parameterized.class)
    public static class Conf2RulesTest {

        private final DefaultPasswordRuleConf conf;
        private final boolean expectException;

        public Conf2RulesTest(DefaultPasswordRuleConf conf, boolean expectException) {
            this.conf = conf;
            this.expectException = expectException;
        }

        @Parameterized.Parameters(name = "Test case: conf={0}, expectException={1}")
        public static Collection<Object[]> data() {

            DefaultPasswordRuleConf validConf = new DefaultPasswordRuleConf();
            validConf.setMinLength(5);
            validConf.setMaxLength(10);
            validConf.setAlphabetical(3);
            validConf.setDigit(2);
            validConf.getIllegalChars().add('@');

            //JACOCO
            validConf.setUppercase(2);
            validConf.setLowercase(2);
            validConf.setSpecial(2);
            validConf.setRepeatSame(2);
            validConf.setUsernameAllowed(true);
            //fine jacoco



            DefaultPasswordRuleConf invalidConf1 = new DefaultPasswordRuleConf();
            invalidConf1.setMinLength(10);
            invalidConf1.setMaxLength(5);
            invalidConf1.getIllegalChars().add('@');


            DefaultPasswordRuleConf invalidConf2 = new DefaultPasswordRuleConf();
            invalidConf2.setMinLength(5);
            invalidConf2.setMaxLength(10);
            invalidConf2.getSpecialChars().add('@');
            invalidConf2.getIllegalChars().add('@');


            return Arrays.asList(new Object[][]{
                    {validConf, false},
                    {invalidConf1, false}, //true
                    {invalidConf2, false}, //true
                    {null, true},
            });
        }

        @Test
        public void testConf2Rules() {
            try {
                List<Rule> rules = DefaultPasswordRule.conf2Rules(conf);

                if (expectException) {
                    fail("Expected an exception for configuration: " + conf);
                } else {
                    assertNotNull("Rules list should not be null for valid configuration.", rules);
                    assertFalse("Rules list should not be empty for valid configuration.", rules.isEmpty());

                    if (conf != null && (conf.getMinLength() > 0 || conf.getMaxLength() > 0 || conf.getAlphabetical() > 0 ||
                            conf.getUppercase() > 0 || conf.getLowercase() > 0 || conf.getDigit() > 0 ||
                            conf.getSpecial() > 0 || !conf.getIllegalChars().isEmpty() || conf.getRepeatSame() > 0 ||
                            !conf.isUsernameAllowed())) {
                        assertFalse("Rules list should not be empty for valid configuration.", rules.isEmpty());
                    } else {
                        assertTrue("Rules list should be empty for invalid configuration.", rules.isEmpty());
                    }

                    rules.forEach(rule -> {
                        if (rule instanceof LengthRule && conf != null) {
                            LengthRule lengthRule = (LengthRule) rule;

                            if (conf.getMinLength() > 0) {
                                assertEquals("Minimum length mismatch", conf.getMinLength(), lengthRule.getMinimumLength());
                            } else {
                                assertEquals("Default minimum length should not be set", 0, lengthRule.getMinimumLength());
                            }

                            if (conf.getMaxLength() > 0) {
                                assertEquals("Maximum length mismatch", conf.getMaxLength(), lengthRule.getMaximumLength());
                            }
                        } else if (rule instanceof IllegalCharacterRule && conf != null) {
                            IllegalCharacterRule illegalCharacterRule = (IllegalCharacterRule) rule;

                            assertNotNull("Illegal characters should not be null", conf.getIllegalChars());
                            if (!conf.getIllegalChars().isEmpty()) {
                                char[] illegalChars = ArrayUtils.toPrimitive(
                                        conf.getIllegalChars().toArray(Character[]::new));
                                assertNotNull("Illegal characters array should not be null", illegalChars);
                                assertArrayEquals("Illegal characters mismatch",
                                        ArrayUtils.toPrimitive(conf.getIllegalChars().toArray(Character[]::new)),
                                        illegalCharacterRule.getIllegalCharacters());
                            }
                        }
                    });

                }
            } catch (IllegalArgumentException e) {
                if (!expectException) {
                    fail("Did not expect an exception for configuration: " + conf);
                }
            } catch (NullPointerException e) {
                if (!expectException) {
                    fail("Did not expect a NullPointerException for configuration: " + conf);
                }


            } catch (Exception e) {
                fail("Unexpected exception: " + e.getMessage());
            }
        }
    }

    @RunWith(Parameterized.class)
    public static class SetConfTest {

        private final DefaultPasswordRuleConf conf;
        private final boolean expectException;

        public SetConfTest(DefaultPasswordRuleConf conf, boolean expectException) {
            this.conf = conf;
            this.expectException = expectException;
        }

        @Parameterized.Parameters(name = "Test case: conf={0}, expectException={1}")
        public static Collection<Object[]> data() {
            DefaultPasswordRuleConf validConf = new DefaultPasswordRuleConf();
            validConf.setMinLength(5);
            validConf.setMaxLength(10);
            validConf.setAlphabetical(3);
            validConf.setDigit(2);


            DefaultPasswordRuleConf invalidConf1 = new DefaultPasswordRuleConf();
            invalidConf1.setMinLength(10);
            invalidConf1.setMaxLength(5);


            DefaultPasswordRuleConf invalidConf2 = new DefaultPasswordRuleConf();
            invalidConf2.setMinLength(5);
            invalidConf2.setMaxLength(10);
            invalidConf2.getSpecialChars().add('@');
            invalidConf2.getIllegalChars().add('@');

            return Arrays.asList(new Object[][]{
                    {validConf, false},
                    {invalidConf1, false}, //true
                    {invalidConf2, false}, //true
                    {null, true}
            });
        }

        @Test
        public void testSetConf() {
            DefaultPasswordRule rule = new DefaultPasswordRule();

            try {
                rule.setConf(conf);

                if (expectException) {
                    fail("Expected an exception but none was thrown for conf: " + conf);
                }
            } catch (IllegalArgumentException e) {
                if (!expectException) {
                    fail("Did not expect an exception but got: " + e.getMessage());
                }
            } catch (NullPointerException e) {
                if (!expectException) {
                    fail("Did not expect a NullPointerException but got: " + e.getMessage());
                }
            }
        }
    }

    @RunWith(Parameterized.class)
    public static class DefaultPasswordRuleEnforceTest {

        private final ConcreteUser user;
        private final DefaultPasswordRuleConf conf;
        private final boolean expectException;

        public DefaultPasswordRuleEnforceTest(ConcreteUser user, DefaultPasswordRuleConf conf, boolean expectException) {
            this.user = user;
            this.conf = conf;
            this.expectException = expectException;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> data() {
            DefaultPasswordRuleConf validConf = new DefaultPasswordRuleConf();
            validConf.getWordsNotPermitted().add("password");

            ConcreteUser validUser = new ConcreteUser();
            validUser.setUsername("testuser");
            validUser.setPassword("SecurePass!123");
            validUser.setClearPassword("SecurePass!123");


            ConcreteUser invalidUser = new ConcreteUser();
            invalidUser.setUsername("testuser");
            invalidUser.setPassword("password");
            invalidUser.setClearPassword("password");

            ConcreteUser nullUser = new ConcreteUser();

            return Arrays.asList(new Object[][]{
                    {validUser, validConf, false},
                    {invalidUser, validConf, true},
                    {null, validConf, true},
                    //
                    //jacoco
                    {nullUser, validConf, false},
            });
        }

        @Test
        public void testEnforce() {
            DefaultPasswordRule passwordRule = new DefaultPasswordRule();
            passwordRule.setConf(conf);

            try {
                passwordRule.enforce(user);
                if (expectException) {
                    fail("Expected an exception, but none was thrown.");
                }
            } catch (PasswordPolicyException e) {
                if (!expectException) {
                    fail("Did not expect an exception, but got: " + e.getMessage());
                }
            } catch (NullPointerException e) {
                if (!expectException) {
                    fail("Did not expect a NullPointerException, but got: " + e.getMessage());
                }
            }
        }
    }

    public static class GetConfTest {

        @Test
        public void testGetConf() {
            DefaultPasswordRule rule = new DefaultPasswordRule();


            PasswordRuleConf result = rule.getConf();
            assertNull("getConf should return null if no configuration is set.", result);

            DefaultPasswordRuleConf validConf = new DefaultPasswordRuleConf();
            validConf.setMinLength(5);
            validConf.setMaxLength(10);
            rule.setConf(validConf);

            assertNotNull("getConf should not return null after setting a valid configuration.", rule.getConf());
            assertEquals("The returned configuration should match the one set.", validConf, rule.getConf());
        }
    }


}
