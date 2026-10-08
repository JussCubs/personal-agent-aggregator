import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  AggregatorError,
  cleanText,
  createAesGcmSecretBox,
  decodeCursor,
  encodeCursor,
  generateClaimCode,
  generateToken,
  generateWebhookSecret,
  hashToken,
  isPublicAddress,
  normalizeClaimCode,
  parseAuthorizeRequest,
  pkceChallengeS256,
  resolvePublicDestination,
  signWebhook,
  validateClientMetadataDocument,
  validateOutboundUrl,
  validateRegistrationRequest,
  verifyPkceS256,
  verifyWebhook,
  webhookHeaders,
  wwwAuthenticate,
} from "../dist/index.js";

test("outbound URL guard blocks private, reserved and tricky destinations", async () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::1.2.3.4", "2001:db8::1", "2002::1", "::"]) {
    assert.equal(isPublicAddress(ip), false, ip);
  }
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) assert.equal(isPublicAddress(ip), true, ip);
  for (const url of ["http://example.com/x", "https://user:pw@example.com/", "https://localhost/x", "https://foo.internal/x", "https://127.0.0.1/x", "https://[::1]/x", "https://2130706433/x", "https://0x7f.1/x", "https://example.com:22/x", "ftp://example.com", "https://metadata/x"]) {
    assert.throws(() => validateOutboundUrl(url), AggregatorError, url);
  }
  assert.equal(validateOutboundUrl("https://hooks.example.com/r/abc?x=1").host, "hooks.example.com");
  await assert.rejects(resolvePublicDestination(new URL("https://rebind.example.com/"), { resolver: async () => [{ address: "8.8.8.8", family: 4 }, { address: "10.0.0.5", family: 4 }] }), AggregatorError);
  const ok = await resolvePublicDestination(new URL("https://ok.example.com/"), { resolver: async () => [{ address: "93.184.216.34", family: 4 }] });
  assert.equal(ok.address, "93.184.216.34");
});

test("Standard Webhooks signatures verify, rotate and expire", () => {
  const secret = generateWebhookSecret();
  const old = generateWebhookSecret();
  const body = JSON.stringify({ eventId: "evt_1", name: "answer.created" });
  const now = new Date("2026-10-01T00:00:00Z");
  const headers = webhookHeaders([secret, old], "evt_1", body, now);
  assert.match(headers["webhook-signature"], /^v1,\S+ v1,\S+$/);
  assert.ok(verifyWebhook(secret, headers, body, { now }));
  assert.ok(verifyWebhook(old, headers, body, { now }), "previous key still verifies during rotation");
  assert.equal(verifyWebhook(secret, headers, `${body} `, { now }), false, "body tamper");
  assert.equal(verifyWebhook(secret, headers, body, { now: new Date(now.getTime() + 600_000) }), false, "stale timestamp");
  assert.equal(verifyWebhook(generateWebhookSecret(), headers, body, { now }), false, "wrong key");
  // Known-answer: Standard Webhooks signs `${id}.${ts}.${body}` with HMAC-SHA256 over the decoded key.
  const fixed = `whsec_${Buffer.from("0123456789abcdef0123456789abcdef").toString("base64")}`;
  assert.equal(signWebhook(fixed, "msg_1", 1700000000, "{}"), "v1,2c4VI0bO4Wd5svqP2unEA9pCk0dTAXr/elrHCJ+/efk=");
});

test("credentials and setup codes", () => {
  const token = generateToken("agg");
  assert.match(token, /^agg_[A-Za-z0-9_-]{43}$/);
  assert.equal(hashToken(token).length, 64);
  const code = generateClaimCode();
  assert.match(code, /^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$/);
  assert.equal(normalizeClaimCode(code.toLowerCase().replaceAll("-", " ")), code);
  assert.equal(normalizeClaimCode("short"), null);
  const box = createAesGcmSecretBox(randomBytes(32).toString("hex"));
  const sealed = box.encrypt("routine-key");
  assert.notEqual(sealed, "routine-key");
  assert.equal(box.decrypt(sealed), "routine-key");
  assert.throws(() => box.decrypt(sealed.replace(/.$/, (c) => (c === "0" ? "1" : "0"))));
});

test("cursors are opaque and validated", () => {
  assert.equal(decodeCursor(encodeCursor(42)), 42);
  assert.equal(decodeCursor(undefined), 0);
  assert.throws(() => decodeCursor("c1.!!!"), AggregatorError);
  assert.throws(() => decodeCursor("42"), AggregatorError);
});

test("text normalization strips control and bidi characters", () => {
  assert.equal(cleanText("  a‮b\u0000c\r\nd  ", "x", 100), "abc\nd");
  assert.equal(cleanText("x\ny", "x", 100, { multiline: false }), "x y");
  assert.throws(() => cleanText("abcd", "x", 3), AggregatorError);
});

test("OAuth: PKCE, authorize validation, CIMD, DCR, challenges", () => {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = pkceChallengeS256(verifier);
  assert.ok(verifyPkceS256(verifier, challenge));
  assert.equal(verifyPkceS256("short", challenge), false);
  assert.equal(verifyPkceS256(randomBytes(32).toString("base64url"), challenge), false);
  const client = { redirect_uris: ["https://client.example.com/oauth/callback"] };
  const resource = "https://api.example.com/mcp";
  const good = parseAuthorizeRequest({ response_type: "code", client_id: "c", redirect_uri: client.redirect_uris[0], state: "s", code_challenge: challenge, code_challenge_method: "S256", resource }, client, resource);
  assert.equal(good.ok, true);
  const badRedirect = parseAuthorizeRequest({ response_type: "code", client_id: "c", redirect_uri: "https://evil.example/cb", code_challenge: challenge, code_challenge_method: "S256" }, client, resource);
  assert.equal(badRedirect.ok, false);
  assert.equal(badRedirect.error.fatal, true, "an unregistered redirect is never redirected to");
  const plain = parseAuthorizeRequest({ response_type: "code", client_id: "c", redirect_uri: client.redirect_uris[0], code_challenge: challenge, code_challenge_method: "plain" }, client, resource);
  assert.equal(plain.ok, false);
  assert.equal(plain.error.fatal, false);
  const wrongResource = parseAuthorizeRequest({ response_type: "code", client_id: "c", redirect_uri: client.redirect_uris[0], code_challenge: challenge, code_challenge_method: "S256", resource: "https://other/mcp" }, client, resource);
  assert.equal(wrongResource.error.error, "invalid_target");
  const cimdUrl = "https://client.example.com/oauth/client.json";
  assert.ok(validateClientMetadataDocument(cimdUrl, { client_id: cimdUrl, client_name: "Example MCP client", redirect_uris: client.redirect_uris }));
  assert.equal(validateClientMetadataDocument(cimdUrl, { client_id: "https://evil/x.json", redirect_uris: client.redirect_uris }), null, "document must name itself");
  assert.equal(validateRegistrationRequest({ redirect_uris: ["http://evil.example/cb"] }).ok, false);
  assert.equal(validateRegistrationRequest({ redirect_uris: ["https://ok.example/cb"], token_endpoint_auth_method: "client_secret_basic" }).ok, false);
  assert.equal(validateRegistrationRequest({ redirect_uris: ["https://ok.example/cb"], client_name: "App" }).ok, true);
  assert.match(wwwAuthenticate({ resourceMetadataUrl: "https://x/.well-known/oauth-protected-resource", scope: ["hub:read"], error: "insufficient_scope" }), /^Bearer resource_metadata="[^"]+", scope="hub:read", error="insufficient_scope"$/);
});
