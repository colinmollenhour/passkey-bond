package bond.passkey.app;

import android.util.Base64;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import org.json.JSONArray;
import org.json.JSONObject;

final class WebAuthnNative {
    static final String TYPE_PUBLIC_KEY_CREDENTIAL = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL";
    static final String TYPE_PUBLIC_KEY_CREDENTIAL_ALT = "android.credentials.TYPE_PUBLIC_KEY_CREDENTIAL";
    static final String KEY_AUTH_RESPONSE_JSON =
            "androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON";
    static final String KEY_REG_RESPONSE_JSON =
            "androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON";
    static final String KEY_SUBTYPE = "androidx.credentials.BUNDLE_KEY_SUBTYPE";

    private static final SecureRandom RANDOM = new SecureRandom();
    // Passkey.bond AAGUID 2391d29c-2806-4960-a51b-7c18e5da7976 — must stay
    // byte-identical to the web (cbor.ts) and iOS (WebAuthn.swift) values.
    // See docs/aaguid/README.md.
    private static final byte[] AAGUID = new byte[] {
        0x23, (byte) 0x91, (byte) 0xd2, (byte) 0x9c,
        0x28, 0x06, 0x49, 0x60,
        (byte) 0xa5, 0x1b, 0x7c, 0x18,
        (byte) 0xe5, (byte) 0xda, 0x79, 0x76
    };

    private WebAuthnNative() {}

    static boolean isPublicKeyType(String type) {
        return type != null
                && (TYPE_PUBLIC_KEY_CREDENTIAL.equals(type)
                        || TYPE_PUBLIC_KEY_CREDENTIAL_ALT.equals(type)
                        || "public-key".equals(type)
                        || type.contains("PUBLIC_KEY_CREDENTIAL"));
    }

    static ProviderVaultStore.PasskeyRecord createPasskey(
            String requestJson,
            String origin) throws Exception {
        String rpId = ProviderVaultStore.rpIdFromRequestJson(requestJson);
        if (rpId == null || rpId.length() == 0) {
            throw new IllegalArgumentException("Create request is missing rpId");
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        KeyPair keyPair = generator.generateKeyPair();

        byte[] credentialId = randomBytes(32);
        String credentialIdB64 = base64Url(credentialId);
        byte[] publicKeyRaw = rawPublicKey((ECPublicKey) keyPair.getPublic());

        ProviderVaultStore.PasskeyRecord record = new ProviderVaultStore.PasskeyRecord();
        record.id = credentialIdB64;
        record.credentialId = credentialIdB64;
        record.rpId = rpId;
        record.origin = finalOrigin(origin, rpId);
        record.userId = ProviderVaultStore.userIdFromCreateRequest(requestJson);
        record.userName = ProviderVaultStore.userNameFromCreateRequest(requestJson);
        record.displayName = ProviderVaultStore.displayNameFromCreateRequest(requestJson);
        record.privateKey = Base64.encodeToString(keyPair.getPrivate().getEncoded(), Base64.NO_WRAP);
        record.publicKey = Base64.encodeToString(publicKeyRaw, Base64.NO_WRAP);
        record.createdAt = System.currentTimeMillis();
        record.counter = 0;
        // The vault syncs its passkeys, so a new one is backup eligible. BE is
        // fixed for the credential's life; BS stays off until it is backed up.
        record.backupEligible = true;
        record.backupState = false;
        record.backupSource = "created";
        record.source = new JSONObject();
        return record;
    }

    static String registrationResponseJson(
            ProviderVaultStore.PasskeyRecord passkey,
            String requestJson,
            String origin) throws Exception {
        return registrationResponseJson(passkey, requestJson, origin, false);
    }

    static String registrationResponseJson(
            ProviderVaultStore.PasskeyRecord passkey,
            String requestJson,
            String origin,
            boolean userVerified) throws Exception {
        String challenge = ProviderVaultStore.challengeFromRequestJson(requestJson);
        byte[] credentialId = base64UrlDecode(passkey.credentialId);
        byte[] publicKeyRaw = Base64.decode(passkey.publicKey, Base64.DEFAULT);
        byte[] coseKey = cosePublicKey(publicKeyRaw);
        byte[] authData = authenticatorData(passkey.rpId, credentialId, coseKey, true, 0, userVerified, backupFlags(passkey));
        byte[] attestationObject = attestationObject(authData);
        byte[] clientData = clientDataJson("webauthn.create", challenge, finalOrigin(origin, passkey.rpId));

        JSONObject response = new JSONObject();
        response.put("clientDataJSON", base64Url(clientData));
        response.put("attestationObject", base64Url(attestationObject));
        response.put("authenticatorData", base64Url(authData));
        // RegistrationResponseJSON carries the key as SubjectPublicKeyInfo DER,
        // not COSE; Chrome rejects the whole response otherwise.
        response.put("publicKey", base64Url(spkiPublicKey(publicKeyRaw)));
        response.put("publicKeyAlgorithm", -7);
        response.put("transports", new JSONArray().put("internal"));

        JSONObject out = new JSONObject();
        out.put("id", passkey.credentialId);
        out.put("rawId", passkey.credentialId);
        out.put("type", "public-key");
        out.put("authenticatorAttachment", "platform");
        out.put("response", response);
        out.put("clientExtensionResults", new JSONObject());
        return out.toString();
    }

    static String authenticationResponseJson(
            ProviderVaultStore.PasskeyRecord passkey,
            String requestJson,
            String origin) throws Exception {
        return authenticationResponseJson(passkey, requestJson, origin, null);
    }

    static String authenticationResponseJson(
            ProviderVaultStore.PasskeyRecord passkey,
            String requestJson,
            String origin,
            byte[] callerClientDataHash) throws Exception {
        return authenticationResponseJson(passkey, requestJson, origin, callerClientDataHash, false);
    }

    static String authenticationResponseJson(
            ProviderVaultStore.PasskeyRecord passkey,
            String requestJson,
            String origin,
            byte[] callerClientDataHash,
            boolean userVerified) throws Exception {
        String challenge = ProviderVaultStore.challengeFromRequestJson(requestJson);
        passkey.counter += 1;

        byte[] authData = authenticatorData(passkey.rpId, null, null, false, passkey.counter, userVerified, backupFlags(passkey));
        byte[] clientData = clientDataJson("webauthn.get", challenge, finalOrigin(origin, passkey.rpId));
        // Browsers build their own clientDataJSON and pass its hash; the signature
        // must cover that hash or the RP-side verification fails.
        byte[] clientDataHash = callerClientDataHash != null ? callerClientDataHash : sha256(clientData);
        ByteArrayOutputStream signedBytes = new ByteArrayOutputStream();
        signedBytes.write(authData);
        signedBytes.write(clientDataHash);

        PrivateKey privateKey = privateKey(passkey.privateKey);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(signedBytes.toByteArray());
        byte[] signatureDer = signature.sign();

        JSONObject response = new JSONObject();
        response.put("clientDataJSON", base64Url(clientData));
        response.put("authenticatorData", base64Url(authData));
        response.put("signature", base64Url(signatureDer));
        if (passkey.userId == null || passkey.userId.length() == 0) {
            response.put("userHandle", JSONObject.NULL);
        } else {
            response.put("userHandle", passkey.userId);
        }

        JSONObject out = new JSONObject();
        out.put("id", passkey.credentialId);
        out.put("rawId", passkey.credentialId);
        out.put("type", "public-key");
        out.put("authenticatorAttachment", "platform");
        out.put("response", response);
        out.put("clientExtensionResults", new JSONObject());
        return out.toString();
    }

    private static String finalOrigin(String origin, String rpId) {
        if (origin == null || origin.length() == 0) {
            throw new IllegalArgumentException("Credential request has no verified origin");
        }
        return origin;
    }

    private static PrivateKey privateKey(String privateKeyB64) throws Exception {
        byte[] encoded = Base64.decode(privateKeyB64, Base64.DEFAULT);
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private static byte[] clientDataJson(String type, String challenge, String origin) throws Exception {
        JSONObject clientData = new JSONObject();
        clientData.put("type", type);
        clientData.put("challenge", challenge == null ? "" : challenge);
        clientData.put("origin", origin);
        clientData.put("crossOrigin", false);
        return clientData.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * BE (0x08) and BS (0x10) from the passkey's own record. Relying parties
     * such as Teleport store BE and reject a sign-in that changes it, so these
     * must match what the passkey was created or imported with. A record from
     * before per-credential flags signs with neither, as this app always did.
     */
    static int backupFlags(ProviderVaultStore.PasskeyRecord passkey) {
        if (!Boolean.TRUE.equals(passkey.backupEligible)) return 0;
        return Boolean.TRUE.equals(passkey.backupState) ? 0x18 : 0x08;
    }

    private static byte[] authenticatorData(
            String rpId,
            byte[] credentialId,
            byte[] cosePublicKey,
            boolean includeAttestedCredentialData,
            long counter,
            boolean userVerified,
            int backupFlags) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        int flags = includeAttestedCredentialData ? 0x41 : 0x01;
        if (userVerified) flags |= 0x04;
        flags |= backupFlags;
        out.write(flags);
        out.write(ByteBuffer.allocate(4).putInt((int) counter).array());
        if (includeAttestedCredentialData) {
            out.write(AAGUID);
            out.write((credentialId.length >> 8) & 0xff);
            out.write(credentialId.length & 0xff);
            out.write(credentialId);
            out.write(cosePublicKey);
        }
        return out.toByteArray();
    }

    private static byte[] attestationObject(byte[] authData) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeMap(out, 3);
        writeText(out, "fmt");
        writeText(out, "none");
        writeText(out, "attStmt");
        writeMap(out, 0);
        writeText(out, "authData");
        writeBytes(out, authData);
        return out.toByteArray();
    }

    private static byte[] cosePublicKey(byte[] rawPublicKey) throws Exception {
        if (rawPublicKey.length != 65 || rawPublicKey[0] != 0x04) {
            throw new IllegalArgumentException("Expected uncompressed P-256 public key");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeMap(out, 5);
        writeInt(out, 1);
        writeInt(out, 2);
        writeInt(out, 3);
        writeInt(out, -7);
        writeInt(out, -1);
        writeInt(out, 1);
        writeInt(out, -2);
        writeBytes(out, slice(rawPublicKey, 1, 32));
        writeInt(out, -3);
        writeBytes(out, slice(rawPublicKey, 33, 32));
        return out.toByteArray();
    }

    // DER header of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1),
    // followed by the 65-byte uncompressed point.
    private static final byte[] P256_SPKI_PREFIX = {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};

    static byte[] spkiPublicKey(byte[] rawPublicKey) {
        if (rawPublicKey.length != 65 || rawPublicKey[0] != 0x04) {
            throw new IllegalArgumentException("Expected uncompressed P-256 public key");
        }
        byte[] out = new byte[P256_SPKI_PREFIX.length + rawPublicKey.length];
        System.arraycopy(P256_SPKI_PREFIX, 0, out, 0, P256_SPKI_PREFIX.length);
        System.arraycopy(rawPublicKey, 0, out, P256_SPKI_PREFIX.length, rawPublicKey.length);
        return out;
    }

    private static byte[] rawPublicKey(ECPublicKey publicKey) {
        byte[] x = unsignedFixed(publicKey.getW().getAffineX(), 32);
        byte[] y = unsignedFixed(publicKey.getW().getAffineY(), 32);
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1, 32);
        System.arraycopy(y, 0, out, 33, 32);
        return out;
    }

    private static byte[] unsignedFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, out, length - copy, copy);
        return out;
    }

    private static byte[] randomBytes(int size) {
        byte[] out = new byte[size];
        RANDOM.nextBytes(out);
        return out;
    }

    private static byte[] sha256(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    private static byte[] slice(byte[] input, int offset, int length) {
        byte[] out = new byte[length];
        System.arraycopy(input, offset, out, 0, length);
        return out;
    }

    private static String base64Url(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static byte[] base64UrlDecode(String value) {
        return Base64.decode(value, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static void writeMap(ByteArrayOutputStream out, int length) {
        writeType(out, 5, length);
    }

    private static void writeText(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeType(out, 3, bytes.length);
        out.write(bytes, 0, bytes.length);
    }

    private static void writeBytes(ByteArrayOutputStream out, byte[] bytes) {
        writeType(out, 2, bytes.length);
        out.write(bytes, 0, bytes.length);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        if (value >= 0) writeType(out, 0, value);
        else writeType(out, 1, -1 - value);
    }

    private static void writeType(ByteArrayOutputStream out, int major, int value) {
        int prefix = major << 5;
        if (value < 24) {
            out.write(prefix | value);
        } else if (value < 256) {
            out.write(prefix | 24);
            out.write(value);
        } else {
            out.write(prefix | 25);
            out.write((value >> 8) & 0xff);
            out.write(value & 0xff);
        }
    }
}
