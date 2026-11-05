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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.namespace.QName;

import org.apache.neethi.builders.PolicyContainingPrimitiveAssertion;
import org.apache.neethi.builders.PrimitiveAssertion;

import static org.apache.neethi.PolicyReference.MAX_REMOTE_POLICY_BYTES_PROPERTY;

import org.junit.Test;

/**
 * Tests for PolicyReference URI scheme validation (CWE-918 / SSRF hardening).
 *
 * getRemoteReferencedPolicy() must only allow http and https schemes and must
 * reject all others (file://, ftp://, jar://, etc.) before opening any connection.
 */
public class PolicyReferenceTest extends PolicyTestCase {

    /**
     * Loads a policy from test-policy-reference.xml and verifies the policy name
     * is parsed correctly. Normalization is not called, so no outbound call is made.
     */
    @Test
    public void testGetPolicyFromPolicyReferenceFile() throws Exception {
        Policy policy = getPolicy("samples/test-policy-reference.xml");
        assertNotNull(policy);
        assertEquals("OuterPolicy", policy.getName());
    }

    // -----------------------------------------------------------------------
    // Scheme allow-list: blocked schemes
    // -----------------------------------------------------------------------

    @Test(expected = RuntimeException.class)
    public void testFileSchemeIsRejected() throws Exception {
        File policyFile = new File(baseDir, testResourceDir + File.separator
                + "samples" + File.separator + "test-policy-reference.xml");
        PolicyReference ref = new PolicyReference(policyEngine);
        ref.getRemoteReferencedPolicy(policyFile.toURI().toString()); // file:///...
    }

    @Test(expected = RuntimeException.class)
    public void testFtpSchemeIsRejected() throws Exception {
        PolicyReference ref = new PolicyReference(policyEngine);
        ref.getRemoteReferencedPolicy("ftp://example.com/policy.xml");
    }

    @Test(expected = RuntimeException.class)
    public void testJarSchemeIsRejected() throws Exception {
        PolicyReference ref = new PolicyReference(policyEngine);
        ref.getRemoteReferencedPolicy("jar:file:///some.jar!/policy.xml");
    }

    @Test(expected = RuntimeException.class)
    public void testMalformedUriIsRejected() throws Exception {
        PolicyReference ref = new PolicyReference(policyEngine);
        ref.getRemoteReferencedPolicy("not a url at all");
    }

    // -----------------------------------------------------------------------
    // Scheme allow-list: ftp:// must not trigger an outbound connection
    // -----------------------------------------------------------------------

    /**
     * Verifies that a ftp:// URI is rejected BEFORE any TCP connection is made.
     * Opens a local ServerSocket and confirms no connection arrives within the
     * timeout after the call is rejected.
     */
    @Test
    public void testFtpSchemeDoesNotTriggerOutboundConnection() throws Exception {
        final AtomicBoolean connectionReceived = new AtomicBoolean(false);
        final CountDownLatch latch = new CountDownLatch(1);

        try (final ServerSocket server = new ServerSocket(0)) {
            server.setSoTimeout(500);
            final int port = server.getLocalPort();

            Thread acceptThread = new Thread(new Runnable() {
                public void run() {
                    try {
                        Socket accepted = server.accept();
                        connectionReceived.set(true);
                        accepted.close();
                    } catch (IOException ignored) {
                        // timeout — expected: no connection should arrive
                    } finally {
                        latch.countDown();
                    }
                }
            });
            acceptThread.setDaemon(true);
            acceptThread.start();

            PolicyReference ref = new PolicyReference(policyEngine);
            try {
                ref.getRemoteReferencedPolicy("ftp://127.0.0.1:" + port + "/policy.xml");
                fail("Expected RuntimeException for ftp:// scheme");
            } catch (RuntimeException expected) {
                // correct — rejected before connecting
            }

            latch.await(1, TimeUnit.SECONDS);
        }

        assertFalse(
            "ftp:// scheme triggered an outbound TCP connection — scheme allow-list not enforced",
            connectionReceived.get());
    }

    // -----------------------------------------------------------------------
    // Scheme allow-list: http and https are permitted
    // -----------------------------------------------------------------------

    /**
     * Verifies that http:// URIs are accepted by the scheme check (the connection
     * will fail with a RuntimeException due to the server refusing/not existing,
     * but the exception must NOT be about an unsupported scheme).
     */
    @Test
    public void testHttpSchemeIsPermitted() {
        PolicyReference ref = new PolicyReference(policyEngine);
        try {
            // Use a port that will immediately refuse the connection so the test
            // does not block, but the scheme validation must pass.
            ref.getRemoteReferencedPolicy("http://127.0.0.1:1/policy.xml");
            fail("Expected RuntimeException due to connection failure");
        } catch (RuntimeException e) {
            assertFalse(
                "http:// was rejected by scheme allow-list — it should be permitted",
                e.getMessage().contains("Unsupported URI scheme"));
        }
    }

    @Test
    public void testHttpsSchemeIsPermitted() {
        PolicyReference ref = new PolicyReference(policyEngine);
        try {
            ref.getRemoteReferencedPolicy("https://127.0.0.1:1/policy.xml");
            fail("Expected RuntimeException due to connection failure");
        } catch (RuntimeException e) {
            assertFalse(
                "https:// was rejected by scheme allow-list — it should be permitted",
                e.getMessage().contains("Unsupported URI scheme"));
        }
    }

    // -----------------------------------------------------------------------
    // Error messages must not echo the attacker-supplied URI
    // -----------------------------------------------------------------------

    @Test
    public void testErrorMessagesDoNotEchoUri() {
        PolicyReference ref = new PolicyReference(policyEngine);
        try {
            ref.getRemoteReferencedPolicy("ftp://secret-host.example/policy.xml");
            fail("Expected RuntimeException for ftp:// scheme");
        } catch (RuntimeException e) {
            assertFalse(e.getMessage().contains("secret-host"));
        }
        try {
            ref.getRemoteReferencedPolicy("http://127.0.0.1:1/secret-path.xml");
            fail("Expected RuntimeException due to connection failure");
        } catch (RuntimeException e) {
            assertFalse(e.getMessage().contains("secret-path"));
        }
    }

    // -----------------------------------------------------------------------
    // Forbidden destination addresses are rejected before connecting
    // -----------------------------------------------------------------------

    @Test
    public void testCloudMetadataAddressesAreRejected() {
        String[] uris = {
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/latest/meta-data/",
            "http://[fe80::1]/policy.xml",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[64:ff9b::a9fe:a9fe]/latest/meta-data/",
            "http://224.0.0.1/policy.xml",
        };
        PolicyReference ref = new PolicyReference(policyEngine);
        for (String uri : uris) {
            try {
                ref.getRemoteReferencedPolicy(uri);
                fail("Expected forbidden-address rejection for " + uri);
            } catch (RuntimeException e) {
                assertTrue("Unexpected failure for " + uri + ": " + e.getMessage(),
                    e.getMessage().contains("forbidden address"));
            }
        }
    }

    /**
     * 0.0.0.0 is routed to the local host on common platforms, so it must be
     * rejected before any TCP connection is made.
     */
    @Test
    public void testWildcardAddressDoesNotTriggerOutboundConnection() throws Exception {
        OneShotHttpServer server = new OneShotHttpServer(okResponse(REMOTE_POLICY));
        try {
            PolicyReference ref = new PolicyReference(policyEngine);
            try {
                ref.getRemoteReferencedPolicy("http://0.0.0.0:" + server.getPort() + "/policy.xml");
                fail("Expected RuntimeException for the wildcard address");
            } catch (RuntimeException expected) {
                assertTrue(expected.getMessage().contains("forbidden address"));
            }
            assertFalse("0.0.0.0 triggered an outbound TCP connection", server.isConnected());
        } finally {
            server.close();
        }
    }

    // -----------------------------------------------------------------------
    // Redirects are not followed
    // -----------------------------------------------------------------------

    @Test
    public void testRedirectIsNotFollowed() throws Exception {
        OneShotHttpServer target = new OneShotHttpServer(okResponse(REMOTE_POLICY));
        OneShotHttpServer redirector = null;
        try {
            redirector = new OneShotHttpServer(
                "HTTP/1.1 302 Found\r\n"
                + "Location: http://127.0.0.1:" + target.getPort() + "/policy.xml\r\n"
                + "Content-Length: 0\r\n"
                + "Connection: close\r\n\r\n");
            PolicyReference ref = new PolicyReference(policyEngine);
            Policy policy = null;
            try {
                policy = ref.getRemoteReferencedPolicy(
                    "http://127.0.0.1:" + redirector.getPort() + "/policy.xml");
            } catch (RuntimeException expected) {
                // the empty 302 body is not a policy document
            }
            assertTrue("the redirecting server was never contacted",
                redirector.awaitDone(5000) && redirector.isConnected());
            assertFalse("redirect was followed to its target", target.isConnected());
            assertTrue(policy == null || !"RemotePolicy".equals(policy.getName()));
        } finally {
            target.close();
            if (redirector != null) {
                redirector.close();
            }
        }
    }

    // -----------------------------------------------------------------------
    // DNS-rebinding defence: http connections are pinned to the vetted address
    // -----------------------------------------------------------------------

    @Test
    public void testHttpConnectionIsPinnedToVettedAddress() throws Exception {
        OneShotHttpServer server = new OneShotHttpServer(okResponse(REMOTE_POLICY));
        try {
            PolicyReference ref = new PolicyReference(policyEngine);
            Policy policy = ref.getRemoteReferencedPolicy(
                "http://localhost:" + server.getPort() + "/policy.xml");
            assertNotNull(policy);
            assertEquals("RemotePolicy", policy.getName());
            assertTrue(server.awaitDone(5000));
            String host = server.getHostHeader();
            assertNotNull(host);
            assertFalse("connection was not pinned to the vetted address: Host=" + host,
                host.toLowerCase().startsWith("localhost"));
        } finally {
            server.close();
        }
    }

    @Test
    public void testAddressPinningCanBeDisabled() throws Exception {
        String old = System.getProperty(PolicyReference.PIN_ADDRESS_PROPERTY);
        System.setProperty(PolicyReference.PIN_ADDRESS_PROPERTY, "false");
        OneShotHttpServer server = new OneShotHttpServer(okResponse(REMOTE_POLICY));
        try {
            PolicyReference ref = new PolicyReference(policyEngine);
            Policy policy = ref.getRemoteReferencedPolicy(
                "http://localhost:" + server.getPort() + "/policy.xml");
            assertNotNull(policy);
            assertTrue(server.awaitDone(5000));
            assertEquals("localhost:" + server.getPort(), server.getHostHeader());
        } finally {
            server.close();
            if (old == null) {
                System.clearProperty(PolicyReference.PIN_ADDRESS_PROPERTY);
            } else {
                System.setProperty(PolicyReference.PIN_ADDRESS_PROPERTY, old);
            }
        }
    }

    /**
     * Ensures circular references are detected for policies with explicit Id values.
     */
    @Test
    public void testCircularPolicyReferenceWithIdsIsDetected() {
        // Build Policy A: ExactlyOne > All > PolicyReference("B")
        PolicyReference refToB = new PolicyReference();
        refToB.setURI("B");
        All allA = new All();
        allA.addPolicyComponent(refToB);
        ExactlyOne eoA = new ExactlyOne();
        eoA.addPolicyComponent(allA);
        Policy policyA = new Policy(registry);
        policyA.setId("A");
        policyA.addPolicyComponent(eoA);

        // Build Policy B: ExactlyOne > All > PolicyReference("A")
        PolicyReference refToA = new PolicyReference();
        refToA.setURI("A");
        All allB = new All();
        allB.addPolicyComponent(refToA);
        ExactlyOne eoB = new ExactlyOne();
        eoB.addPolicyComponent(allB);
        Policy policyB = new Policy(registry);
        policyB.setId("B");
        policyB.addPolicyComponent(eoB);

        registry.register("A", policyA);
        registry.register("B", policyB);

        try {
            policyA.normalize(registry, true);
            fail("Expected RuntimeException due to circular reference");
        } catch (RuntimeException e) {
            assertTrue(
                "Expected a cycle-detection message but got: " + e.getMessage(),
                e.getMessage() != null && e.getMessage().toLowerCase().contains("circular"));
        }
    }

    /**
     * Ensures circular references are detected even when referenced policies have no Id.
     *
     * Cycle detection must use a stable non-null resolution token so that
     * no-Id references cannot bypass the resolving set.
     */
    @Test
    public void testCircularPolicyReferenceWithoutIdsIsDetected() {
        // Policy A references registry key "B" but has no policy Id.
        PolicyReference refToB = new PolicyReference();
        refToB.setURI("B");
        All allA = new All();
        allA.addPolicyComponent(refToB);
        ExactlyOne eoA = new ExactlyOne();
        eoA.addPolicyComponent(allA);
        Policy policyA = new Policy(registry);
        policyA.addPolicyComponent(eoA);

        // Policy B references registry key "A" and also has no policy Id.
        PolicyReference refToA = new PolicyReference();
        refToA.setURI("A");
        All allB = new All();
        allB.addPolicyComponent(refToA);
        ExactlyOne eoB = new ExactlyOne();
        eoB.addPolicyComponent(allB);
        Policy policyB = new Policy(registry);
        policyB.addPolicyComponent(eoB);

        registry.register("A", policyA);
        registry.register("B", policyB);

        try {
            policyA.normalize(registry, true);
            fail("Expected RuntimeException due to circular reference");
        } catch (RuntimeException e) {
            assertTrue(
                "Expected a cycle-detection message but got: " + e.getMessage(),
                e.getMessage() != null && e.getMessage().toLowerCase().contains("circular"));
        }
    }

    /**
     * Ensures a circular reference between two policies defined locally in a parsed
     * policy document ("#A" references "#B", which references "#A") is detected.
     */
    @Test
    public void testCircularLocalPolicyReferenceInDocumentIsDetected() throws Exception {
        String xml = "<wsp:Policy xmlns:wsp=\"" + Constants.URI_POLICY_15_NS + "\""
            + " xmlns:wsu=\"" + Constants.URI_WSU_NS + "\">"
            + "<wsp:Policy wsu:Id=\"A\"><wsp:PolicyReference URI=\"#B\"/></wsp:Policy>"
            + "<wsp:Policy wsu:Id=\"B\"><wsp:PolicyReference URI=\"#A\"/></wsp:Policy>"
            + "</wsp:Policy>";
        Policy policy = policyEngine.getPolicy(new ByteArrayInputStream(xml.getBytes("UTF-8")));

        try {
            policy.normalize(registry, true);
            fail("Expected RuntimeException due to circular reference");
        } catch (RuntimeException e) {
            assertTrue(
                "Expected a cycle-detection message but got: " + e.getMessage(),
                e.getMessage() != null && e.getMessage().toLowerCase().contains("circular"));
        }
    }

    /**
     * Ensures a circular reference is detected when it runs through the nested Policy of an
     * assertion: normalizing the assertion normalizes its nested Policy on its own, which
     * must still see the references that are already being resolved.
     */
    @Test
    public void testCircularPolicyReferenceThroughNestedAssertionPolicyIsDetected() {
        // Policy A: ExactlyOne > All > Wrapper assertion > nested Policy > PolicyReference("A")
        PolicyReference refToA = new PolicyReference();
        refToA.setURI("A");
        Policy nested = new Policy(registry);
        nested.addPolicyComponent(refToA);
        All allA = new All();
        allA.addPolicyComponent(new PolicyContainingPrimitiveAssertion(
            new QName("urn:neethi:test", "Wrapper"), false, false, nested));
        ExactlyOne eoA = new ExactlyOne();
        eoA.addPolicyComponent(allA);
        Policy policyA = new Policy(registry);
        policyA.setId("A");
        policyA.addPolicyComponent(eoA);

        registry.register("A", policyA);

        try {
            policyA.normalize(registry, true);
            fail("Expected RuntimeException due to circular reference");
        } catch (RuntimeException e) {
            assertTrue(
                "Expected a cycle-detection message but got: " + e.getMessage(),
                e.getMessage() != null && e.getMessage().toLowerCase().contains("circular"));
        }
    }

    /**
     * Ensures a Policy that is referenced several times without forming a cycle (directly,
     * and from the nested Policy of an assertion) still normalizes, including right after a
     * circular reference has been rejected on the same thread.
     */
    @Test
    public void testRepeatedNonCircularPolicyReferenceIsNormalized() {
        // Policy C: a single assertion
        Policy policyC = new Policy(registry);
        policyC.setId("C");
        policyC.addPolicyComponent(new PrimitiveAssertion(new QName("urn:neethi:test", "Leaf")));

        // Policy B: All > { PolicyReference("C"), Wrapper assertion > nested Policy > PolicyReference("C") }
        PolicyReference directRefToC = new PolicyReference();
        directRefToC.setURI("C");
        PolicyReference nestedRefToC = new PolicyReference();
        nestedRefToC.setURI("C");
        Policy nested = new Policy(registry);
        nested.addPolicyComponent(nestedRefToC);
        All allB = new All();
        allB.addPolicyComponent(directRefToC);
        allB.addPolicyComponent(new PolicyContainingPrimitiveAssertion(
            new QName("urn:neethi:test", "Wrapper"), false, false, nested));
        ExactlyOne eoB = new ExactlyOne();
        eoB.addPolicyComponent(allB);
        Policy policyB = new Policy(registry);
        policyB.setId("B");
        policyB.addPolicyComponent(eoB);

        // Policy A: All > { PolicyReference("B"), PolicyReference("B") }
        PolicyReference firstRefToB = new PolicyReference();
        firstRefToB.setURI("B");
        PolicyReference secondRefToB = new PolicyReference();
        secondRefToB.setURI("B");
        All allA = new All();
        allA.addPolicyComponent(firstRefToB);
        allA.addPolicyComponent(secondRefToB);
        ExactlyOne eoA = new ExactlyOne();
        eoA.addPolicyComponent(allA);
        Policy policyA = new Policy(registry);
        policyA.setId("A");
        policyA.addPolicyComponent(eoA);

        // First make C circular (C -> A -> B -> C) and check that the cycle is rejected.
        PolicyReference refToA = new PolicyReference();
        refToA.setURI("A");
        policyC.addPolicyComponent(refToA);
        registry.register("A", policyA);
        registry.register("B", policyB);
        registry.register("C", policyC);
        try {
            policyA.normalize(registry, true);
            fail("Expected RuntimeException due to circular reference");
        } catch (RuntimeException e) {
            assertTrue(
                "Expected a cycle-detection message but got: " + e.getMessage(),
                e.getMessage() != null && e.getMessage().toLowerCase().contains("circular"));
        }

        // Break the cycle: the repeated references must now normalize to one alternative.
        policyC.getPolicyComponents().remove(refToA);
        Policy normalized = policyA.normalize(registry, true);
        Iterator<List<Assertion>> alternatives = normalized.getAlternatives();
        assertTrue(alternatives.hasNext());
        assertEquals(4, alternatives.next().size());
        assertFalse(alternatives.hasNext());
    }

    @Test
    public void testRemotePolicyDeclaredContentLengthAboveLimitIsRejected() throws Exception {
        String previous = System.getProperty(MAX_REMOTE_POLICY_BYTES_PROPERTY);
        System.setProperty(MAX_REMOTE_POLICY_BYTES_PROPERTY, "1024");

        byte[] payload = buildLargePolicyPayload(2048);
        try (LocalHttpServer server = LocalHttpServer.fixedLength(payload)) {
            String url = "http://127.0.0.1:" + server.getPort() + "/policy.xml";
            PolicyReference ref = new PolicyReference(policyEngine);
            try {
                ref.getRemoteReferencedPolicy(url);
                fail("Expected RuntimeException due to remote response byte budget");
            } catch (RuntimeException ex) {
                assertTrue(ex.getMessage().contains("maximum remote policy size"));
            }
        } finally {
            restoreProperty(MAX_REMOTE_POLICY_BYTES_PROPERTY, previous);
        }
    }

    @Test
    public void testRemotePolicyChunkedResponseAboveLimitIsRejected() throws Exception {
        String previous = System.getProperty(MAX_REMOTE_POLICY_BYTES_PROPERTY);
        System.setProperty(MAX_REMOTE_POLICY_BYTES_PROPERTY, "1024");

        byte[] payload = buildLargePolicyPayload(4096);
        try (LocalHttpServer server = LocalHttpServer.chunked(payload)) {
            String url = "http://127.0.0.1:" + server.getPort() + "/policy.xml";
            PolicyReference ref = new PolicyReference(policyEngine);
            try {
                ref.getRemoteReferencedPolicy(url);
                fail("Expected RuntimeException due to remote response byte budget");
            } catch (RuntimeException ex) {
                assertTrue(ex.getMessage().contains("maximum remote policy size"));
            }
        } finally {
            restoreProperty(MAX_REMOTE_POLICY_BYTES_PROPERTY, previous);
        }
    }

    private static void restoreProperty(String key, String previous) {
        if (previous == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, previous);
        }
    }

    private static byte[] buildLargePolicyPayload(int totalBytes) {
        String prefix = "<wsp:Policy xmlns:wsp=\"http://www.w3.org/ns/ws-policy\">";
        String suffix = "</wsp:Policy>";
        int middleSize = Math.max(0, totalBytes - prefix.length() - suffix.length());
        char[] middle = new char[middleSize];
        Arrays.fill(middle, ' ');
        String xml = prefix + new String(middle) + suffix;
        return xml.getBytes(StandardCharsets.UTF_8);
    }

    private static final class LocalHttpServer implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final Thread serverThread;
        private final byte[] payload;
        private final boolean sendContentLength;
        private final CountDownLatch ready = new CountDownLatch(1);
        private final AtomicBoolean closed = new AtomicBoolean(false);

        static LocalHttpServer fixedLength(byte[] payload) throws IOException {
            return new LocalHttpServer(payload, true);
        }

        static LocalHttpServer chunked(byte[] payload) throws IOException {
            return new LocalHttpServer(payload, false);
        }

        LocalHttpServer(byte[] payload, boolean sendContentLength) throws IOException {
            this.payload = payload;
            this.sendContentLength = sendContentLength;
            this.serverSocket = new ServerSocket(0);
            this.serverThread = new Thread(new Runnable() {
                public void run() {
                    serveOnce();
                }
            }, "policy-reference-test-server");
            this.serverThread.setDaemon(true);
            this.serverThread.start();
            awaitReady();
        }

        int getPort() {
            return serverSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            if (closed.compareAndSet(false, true)) {
                serverSocket.close();
                try {
                    serverThread.join(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        private void awaitReady() throws IOException {
            try {
                if (!ready.await(1, TimeUnit.SECONDS)) {
                    throw new IOException("Test HTTP server did not start in time");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting for test HTTP server", e);
            }
        }

        private void serveOnce() {
            ready.countDown();
            try (Socket client = serverSocket.accept()) {
                consumeRequest(client.getInputStream());
                writeResponse(client.getOutputStream());
            } catch (IOException ignored) {
                // The tests close the server socket during cleanup.
            }
        }

        private void consumeRequest(InputStream input) throws IOException {
            byte[] buffer = new byte[1024];
            int matched = 0;
            while (matched < 4) {
                int read = input.read(buffer);
                if (read == -1) {
                    break;
                }
                for (int i = 0; i < read; i++) {
                    byte b = buffer[i];
                    if ((matched == 0 || matched == 2) && b == '\r') {
                        matched++;
                    } else if ((matched == 1 || matched == 3) && b == '\n') {
                        matched++;
                    } else {
                        matched = 0;
                    }
                    if (matched == 4) {
                        return;
                    }
                }
            }
        }

        private void writeResponse(OutputStream out) throws IOException {
            StringBuilder response = new StringBuilder();
            response.append("HTTP/1.1 200 OK\r\n");
            response.append("Content-Type: application/xml\r\n");
            response.append("Connection: close\r\n");
            if (sendContentLength) {
                response.append("Content-Length: ").append(payload.length).append("\r\n");
            }
            response.append("\r\n");
            out.write(response.toString().getBytes(StandardCharsets.US_ASCII));
            out.write(payload);
            out.flush();
        }
    }

    private static final String REMOTE_POLICY =
        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\""
        + " Name=\"RemotePolicy\"/>";

    private static String okResponse(String body) throws IOException {
        return "HTTP/1.1 200 OK\r\n"
            + "Content-Type: text/xml\r\n"
            + "Content-Length: " + body.getBytes("UTF-8").length + "\r\n"
            + "Connection: close\r\n\r\n"
            + body;
    }

    /**
     * Minimal HTTP server that accepts a single connection, records the Host
     * header of the request, writes a canned response and closes.
     */
    private static final class OneShotHttpServer implements Runnable {
        private final ServerSocket server;
        private final String response;
        private final CountDownLatch done = new CountDownLatch(1);
        private volatile boolean connected;
        private volatile String hostHeader;

        OneShotHttpServer(String response) throws IOException {
            this.response = response;
            this.server = new ServerSocket(0);
            this.server.setSoTimeout(10000);
            Thread thread = new Thread(this);
            thread.setDaemon(true);
            thread.start();
        }

        int getPort() {
            return server.getLocalPort();
        }

        boolean isConnected() {
            return connected;
        }

        String getHostHeader() {
            return hostHeader;
        }

        boolean awaitDone(long millis) throws InterruptedException {
            return done.await(millis, TimeUnit.MILLISECONDS);
        }

        void close() throws IOException {
            server.close();
        }

        public void run() {
            try {
                Socket socket = server.accept();
                connected = true;
                try {
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), "ISO-8859-1"));
                    String line;
                    while ((line = reader.readLine()) != null && line.length() > 0) {
                        if (line.regionMatches(true, 0, "Host:", 0, 5)) {
                            hostHeader = line.substring(5).trim();
                        }
                    }
                    OutputStream out = socket.getOutputStream();
                    out.write(response.getBytes("UTF-8"));
                    out.flush();
                } finally {
                    socket.close();
                }
            } catch (IOException ignored) {
                // accept timed out or the server was closed: no connection arrived
            } finally {
                done.countDown();
            }
        }
    }
}
