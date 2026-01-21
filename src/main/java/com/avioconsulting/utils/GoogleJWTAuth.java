package com.avioconsulting.utils;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class GoogleJWTAuth {

    public static String createJWT(String privateKeyId, String privateKey, String issuer, String user, String scopes, String audience) {
        try {
            // 1. Prepare Key
            // Strip any PEM headers/footers if present (just in case, though usually passed raw base64)
            String cleanKey = privateKey.replace("-----BEGIN PRIVATE KEY-----", "")
                                      .replace("-----END PRIVATE KEY-----", "")
                                      .replaceAll("\\s+", "");
            
            byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(spec);

            // 2. Create Header
            // {"alg":"RS256","typ":"JWT","kid":"<privateKeyId>"}
            String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + privateKeyId + "\"}";
            String headerEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));

            // 3. Create Payload
            long now = System.currentTimeMillis() / 1000;
            long exp = now + 3600; // 1 hour expiration
            
            // Build JSON manually to avoid Jackson dependency
            StringBuilder payload = new StringBuilder();
            payload.append("{");
            payload.append("\"iss\":\"").append(issuer).append("\",");
            if (user != null && !user.isEmpty()) {
                payload.append("\"sub\":\"").append(user).append("\",");
            }
            payload.append("\"aud\":\"").append(audience).append("\",");
            payload.append("\"exp\":").append(exp).append(",");
            payload.append("\"iat\":").append(now).append(",");
            payload.append("\"scope\":\"").append(scopes).append("\"");
            payload.append("}");
            
            String payloadEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));

            // 4. Sign
            String content = headerEncoded + "." + payloadEncoded;
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(rsaPrivateKey);
            signature.update(content.getBytes(StandardCharsets.UTF_8));
            byte[] signBytes = signature.sign();
            String signatureEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(signBytes);

            return content + "." + signatureEncoded;

        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}
