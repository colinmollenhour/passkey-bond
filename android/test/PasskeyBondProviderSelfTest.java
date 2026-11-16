package bond.passkey.app;

import org.json.JSONObject;

public final class PasskeyBondProviderSelfTest {
    public static void main(String[] args) throws Exception {
        JSONObject rp = new JSONObject()
                .put("id", "example.com")
                .put("name", "Example");
        JSONObject user = new JSONObject()
                .put("id", "dXNlci0x")
                .put("name", "ali@example.com")
                .put("displayName", "Ali");
        JSONObject request = new JSONObject()
                .put("challenge", "Y2hhbGxlbmdlLTE")
                .put("rp", rp)
                .put("user", user);

        ProviderVaultStore.PasskeyRecord passkey =
                WebAuthnNative.createPasskey(request.toString(), "https://example.com");
        require("example.com".equals(passkey.rpId), "rpId mismatch");
        require("ali@example.com".equals(passkey.userName), "userName mismatch");
        require(passkey.credentialId != null && passkey.credentialId.length() > 20, "credentialId missing");
        require(passkey.privateKey != null && passkey.privateKey.length() > 100, "privateKey missing");
        require(passkey.publicKey != null && passkey.publicKey.length() > 80, "publicKey missing");

        String registration = WebAuthnNative.registrationResponseJson(
                passkey,
                request.toString(),
                "https://example.com");
        JSONObject registrationJson = new JSONObject(registration);
        require(passkey.credentialId.equals(registrationJson.getString("id")), "registration id mismatch");
        require("public-key".equals(registrationJson.getString("type")), "registration type mismatch");
        JSONObject regResponse = registrationJson.getJSONObject("response");
        require(regResponse.getString("clientDataJSON").length() > 20, "registration clientDataJSON missing");
        require(regResponse.getString("attestationObject").length() > 20, "attestationObject missing");
        // response.publicKey must be SubjectPublicKeyInfo DER that parses as the
        // passkey's own key, as browsers require.
        byte[] spki = android.util.Base64.decode(
                regResponse.getString("publicKey"),
                android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING | android.util.Base64.NO_WRAP);
        java.security.PublicKey parsed = java.security.KeyFactory.getInstance("EC")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
        byte[] raw = android.util.Base64.decode(passkey.publicKey, android.util.Base64.DEFAULT);
        require(parsed instanceof java.security.interfaces.ECPublicKey, "publicKey is not an EC key");
        java.security.spec.ECPoint w = ((java.security.interfaces.ECPublicKey) parsed).getW();
        require(new java.math.BigInteger(1, java.util.Arrays.copyOfRange(raw, 1, 33)).equals(w.getAffineX())
                && new java.math.BigInteger(1, java.util.Arrays.copyOfRange(raw, 33, 65)).equals(w.getAffineY()),
                "publicKey response is not the passkey's key");
        require(regResponse.getInt("publicKeyAlgorithm") == -7, "publicKeyAlgorithm mismatch");

        String authentication = WebAuthnNative.authenticationResponseJson(
                passkey,
                request.toString(),
                "https://example.com");
        JSONObject authenticationJson = new JSONObject(authentication);
        require(passkey.credentialId.equals(authenticationJson.getString("id")), "authentication id mismatch");
        require(passkey.counter == 1, "counter did not increment");
        JSONObject authResponse = authenticationJson.getJSONObject("response");
        require(authResponse.getString("clientDataJSON").length() > 20, "auth clientDataJSON missing");
        require(authResponse.getString("authenticatorData").length() > 20, "authenticatorData missing");
        require(authResponse.getString("signature").length() > 20, "signature missing");

        ProviderVaultStore.PasskeyRecord roundTrip =
                ProviderVaultStore.PasskeyRecord.fromJson(passkey.toJson());
        require(roundTrip != null, "roundTrip parse failed");
        require(passkey.credentialId.equals(roundTrip.credentialId), "roundTrip credentialId mismatch");
        require(passkey.counter == roundTrip.counter, "roundTrip counter mismatch");

        System.out.println(new JSONObject()
                .put("ok", true)
                .put("rpId", passkey.rpId)
                .put("credentialIdLength", passkey.credentialId.length())
                .put("counter", passkey.counter)
                .put("registrationType", registrationJson.getString("type"))
                .put("authenticationType", authenticationJson.getString("type"))
                .toString());
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
