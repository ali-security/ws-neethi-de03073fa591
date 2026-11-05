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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;

import org.junit.Test;

/**
 * Reproduces parser recursion DoS where deeply nested policy operators trigger
 * StackOverflowError during PolicyBuilder.getPolicy(InputStream).
 */
public class PolicyBuilderDoSTest extends PolicyTestCase {

    private static final int DEPTH_WITHIN_DEFAULT_BUDGET = 64;
    private static final int DEPTH_ABOVE_DEFAULT_BUDGET = 4096;
    // Each level adds an assertion and a wsp:Policy element; kept below the element depth
    // limit some StAX readers (e.g. Woodstox) enforce themselves while still exceeding
    // the policy nesting depth budget.
    private static final int ASSERTION_DEPTH_ABOVE_DEFAULT_BUDGET = 400;

    @Test
    public void testDeeplyNestedPolicyIsRejectedByDepthBudget() {
        PolicyBuilder builder = new PolicyBuilder();
        InputStream stream = xmlStream(buildNestedAllPolicyXml(DEPTH_ABOVE_DEFAULT_BUDGET));

        try {
            builder.getPolicy(stream);
            fail("Expected RuntimeException due to policy depth budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("maximum policy nesting depth"));
        }
    }

    @Test
    public void testNestedPolicyWithinDepthBudgetParses() {
        PolicyBuilder builder = new PolicyBuilder();
        InputStream stream = xmlStream(buildNestedAllPolicyXml(DEPTH_WITHIN_DEFAULT_BUDGET));
        Policy policy = builder.getPolicy(stream);

        assertNotNull(policy);
    }

    @Test
    public void testDeeplyNestedExactlyOneIsRejectedByDepthBudget() {
        PolicyBuilder builder = new PolicyBuilder();
        InputStream stream = xmlStream(buildNestedOperatorPolicyXml("ExactlyOne", DEPTH_ABOVE_DEFAULT_BUDGET));

        try {
            builder.getPolicy(stream);
            fail("Expected RuntimeException due to policy depth budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("maximum policy nesting depth"));
        }
    }

    @Test
    public void testDeeplyNestedPolicyElementsAreRejectedByDepthBudget() {
        PolicyBuilder builder = new PolicyBuilder();
        InputStream stream = xmlStream(buildNestedOperatorPolicyXml("Policy", DEPTH_ABOVE_DEFAULT_BUDGET));

        try {
            builder.getPolicy(stream);
            fail("Expected RuntimeException due to policy depth budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("maximum policy nesting depth"));
        }
    }

    @Test
    public void testDeeplyNestedDomPolicyIsRejectedByDepthBudget() throws Exception {
        PolicyBuilder builder = new PolicyBuilder();
        Element element = xmlElement(buildNestedAllPolicyXml(DEPTH_ABOVE_DEFAULT_BUDGET));

        try {
            builder.getPolicy(element);
            fail("Expected RuntimeException due to policy depth budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("maximum policy nesting depth"));
        }
    }

    /**
     * Nested policies inside assertions are built by the AssertionBuilder calling back
     * into PolicyBuilder.getPolicy(..). Those nested calls must not start a fresh depth
     * budget, otherwise alternating wsp:Policy and assertion elements recurses without bound.
     */
    @Test
    public void testNestedAssertionPoliciesCannotBypassDepthBudget() {
        PolicyBuilder builder = new PolicyBuilder();
        InputStream stream = xmlStream(buildNestedAssertionPolicyXml(ASSERTION_DEPTH_ABOVE_DEFAULT_BUDGET));

        try {
            builder.getPolicy(stream);
            fail("Expected RuntimeException due to policy depth budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("maximum policy nesting depth"));
        }
    }

    @Test
    public void testNestedDomAssertionPoliciesCannotBypassDepthBudget() throws Exception {
        PolicyBuilder builder = new PolicyBuilder();
        Element element = xmlElement(buildNestedAssertionPolicyXml(DEPTH_ABOVE_DEFAULT_BUDGET));

        try {
            builder.getPolicy(element);
            fail("Expected RuntimeException due to policy depth budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("maximum policy nesting depth"));
        }
    }

    @Test
    public void testNestedAssertionPoliciesWithinDepthBudgetParse() {
        PolicyBuilder builder = new PolicyBuilder();
        Policy policy = builder.getPolicy(xmlStream(buildNestedAssertionPolicyXml(DEPTH_WITHIN_DEFAULT_BUDGET)));

        assertNotNull(policy);
        assertNotNull(policy.normalize(false));
    }

    @Test
    public void testElementBudgetIsEnforced() {
        PolicyBuilder builder = newBuilderWithLimit("org.apache.neethi.parser.maxElements", "50");
        StringBuilder xml = new StringBuilder();
        xml.append("<wsp:Policy xmlns:wsp=\"http://www.w3.org/ns/ws-policy\">");
        for (int i = 0; i < 100; i++) {
            xml.append("<wsp:All/>");
        }
        xml.append("</wsp:Policy>");

        try {
            builder.getPolicy(xmlStream(xml.toString()));
            fail("Expected RuntimeException due to policy element budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("maximum number of elements"));
        }
    }

    @Test
    public void testAttributeBudgetIsEnforced() {
        PolicyBuilder builder = newBuilderWithLimit("org.apache.neethi.parser.maxAttributes", "5");
        StringBuilder xml = new StringBuilder();
        xml.append("<wsp:Policy xmlns:wsp=\"http://www.w3.org/ns/ws-policy\"");
        for (int i = 0; i < 10; i++) {
            xml.append(" a").append(i).append("=\"v\"");
        }
        xml.append("/>");

        try {
            builder.getPolicy(xmlStream(xml.toString()));
            fail("Expected RuntimeException due to policy attribute budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("maximum number of attributes"));
        }
    }

    @Test
    public void testParseBudgetIsNotSharedAcrossDocuments() {
        PolicyBuilder builder = newBuilderWithLimit("org.apache.neethi.parser.maxElements", "50");
        String xml = buildNestedAssertionPolicyXml(10);

        try {
            builder.getPolicy(xmlStream(buildNestedAssertionPolicyXml(ASSERTION_DEPTH_ABOVE_DEFAULT_BUDGET)));
            fail("Expected RuntimeException due to policy element budget");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("maximum number of elements"));
        }
        for (int i = 0; i < 10; i++) {
            assertNotNull(builder.getPolicy(xmlStream(xml)));
        }
    }

    private static PolicyBuilder newBuilderWithLimit(String property, String value) {
        String old = System.getProperty(property);
        System.setProperty(property, value);
        try {
            return new PolicyBuilder();
        } finally {
            if (old == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, old);
            }
        }
    }

    private static InputStream xmlStream(String xml) {
        return new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static Element xmlElement(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(xmlStream(xml)).getDocumentElement();
    }

    private static String buildNestedOperatorPolicyXml(String operator, int depth) {
        StringBuilder xml = new StringBuilder(128 + (depth * 40));
        xml.append("<wsp:Policy xmlns:wsp=\"http://www.w3.org/ns/ws-policy\">");

        for (int i = 0; i < depth; i++) {
            xml.append("<wsp:").append(operator).append('>');
        }
        for (int i = 0; i < depth; i++) {
            xml.append("</wsp:").append(operator).append('>');
        }

        xml.append("</wsp:Policy>");
        return xml.toString();
    }

    private static String buildNestedAssertionPolicyXml(int depth) {
        StringBuilder xml = new StringBuilder(128 + (depth * 60));
        xml.append("<wsp:Policy xmlns:wsp=\"http://www.w3.org/ns/ws-policy\" xmlns:x=\"urn:neethi:test\">");

        for (int i = 0; i < depth; i++) {
            xml.append("<x:Nested><wsp:Policy>");
        }
        xml.append("<x:Leaf/>");
        for (int i = 0; i < depth; i++) {
            xml.append("</wsp:Policy></x:Nested>");
        }

        xml.append("</wsp:Policy>");
        return xml.toString();
    }

    private static String buildNestedAllPolicyXml(int depth) {
        StringBuilder xml = new StringBuilder(128 + (depth * 20));
        xml.append("<wsp:Policy xmlns:wsp=\"http://www.w3.org/ns/ws-policy\">");

        for (int i = 0; i < depth; i++) {
            xml.append("<wsp:All>");
        }

        xml.append("<wsp:All/>");

        for (int i = 0; i < depth; i++) {
            xml.append("</wsp:All>");
        }

        xml.append("</wsp:Policy>");
        return xml.toString();
    }
}
