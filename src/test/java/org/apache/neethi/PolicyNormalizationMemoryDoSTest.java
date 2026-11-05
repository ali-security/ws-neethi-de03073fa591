/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.neethi;

import javax.xml.namespace.QName;

import org.apache.neethi.builders.PolicyContainingPrimitiveAssertion;
import org.apache.neethi.builders.PrimitiveAssertion;

import org.junit.Test;

/**
 * The 10000-alternatives cap bounds the alternative COUNT of the normalized
 * form, not its memory: every cross-product alternative copies the component
 * lists of both parents, so an ExactlyOne of a few thousand alternatives
 * crossed against a wide All materializes alternatives x width references
 * (hundreds of millions at the parse budgets) while every count check stays
 * green. The materialized-component budget must turn that into a fast,
 * predictable RuntimeException instead of an OutOfMemoryError.
 */
public class PolicyNormalizationMemoryDoSTest extends PolicyTestCase {

    private static final int ALTERNATIVES = 3000;
    private static final int WIDE_ALL_WIDTH = 2000;

    @Test
    public void testWideCrossProductIsRejectedByComponentBudget() {
        Policy policy = buildWideCrossProductPolicy(ALTERNATIVES, WIDE_ALL_WIDTH);

        try {
            policy.normalize(registry, true);
            fail("Expected RuntimeException due to materialized-component budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("materialized components"));
        }
    }

    @Test
    public void testModerateCrossProductStillNormalizes() {
        Policy policy = buildWideCrossProductPolicy(20, 30);

        assertNotNull(policy.normalize(registry, true));
    }

    /**
     * An assertion containing a nested policy normalizes that policy on its own;
     * the nested normalization must keep charging the budget of the outer one, so
     * that splitting the wide content over several such assertions cannot reset it.
     */
    @Test
    public void testNestedPoliciesShareComponentBudget() {
        Policy policy = buildNestedWidePolicy(2, WIDE_ALL_WIDTH);

        try {
            policy.normalize(registry, true);
            fail("Expected RuntimeException due to materialized-component budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("materialized components"));
        }
    }

    @Test
    public void testSingleWideNestedPolicyStillNormalizes() {
        Policy policy = buildNestedWidePolicy(1, WIDE_ALL_WIDTH);

        assertNotNull(policy.normalize(registry, true));
    }

    /**
     * Policy (= All) containing an ExactlyOne of {@code alternatives}
     * single-assertion Alls and one All of {@code width} assertions.
     * Normalization crosses them into {@code alternatives} alternatives of
     * width {@code width + 1} each — count under the cap, memory unbounded.
     */
    private static Policy buildWideCrossProductPolicy(int alternatives, int width) {
        Policy policy = new Policy();

        ExactlyOne eo = new ExactlyOne();
        for (int i = 0; i < alternatives; i++) {
            All alt = new All();
            alt.addPolicyComponent(new PrimitiveAssertion(new QName("urn:test", "a" + i)));
            eo.addPolicyComponent(alt);
        }
        policy.addPolicyComponent(eo);

        All wide = new All();
        for (int i = 0; i < width; i++) {
            wide.addPolicyComponent(new PrimitiveAssertion(new QName("urn:test", "w" + i)));
        }
        policy.addPolicyComponent(wide);

        return policy;
    }

    /**
     * Policy containing {@code wrappers} assertions, each holding a nested
     * Policy of {@code width} assertions.
     */
    private static Policy buildNestedWidePolicy(int wrappers, int width) {
        Policy policy = new Policy();

        for (int w = 0; w < wrappers; w++) {
            Policy nested = new Policy();
            for (int i = 0; i < width; i++) {
                nested.addPolicyComponent(new PrimitiveAssertion(new QName("urn:test", "n" + w + "_" + i)));
            }
            policy.addPolicyComponent(
                new PolicyContainingPrimitiveAssertion(new QName("urn:test", "Wrapper" + w),
                                                       false, false, nested));
        }

        return policy;
    }
}
