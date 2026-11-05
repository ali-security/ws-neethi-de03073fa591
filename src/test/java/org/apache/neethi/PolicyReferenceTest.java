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
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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
