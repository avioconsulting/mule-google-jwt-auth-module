package com.avioconsulting.utils;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.lang.ClassLoader;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.security.Key;
import java.security.KeyFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class authUtils {
	
	@SuppressWarnings("deprecation")
	public static String createJWT(String scopes){
		String result = "";
		try {
			
			//System.out.println("START");
			
			//Find the service account JSON file on the classpath
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			URL resource = classLoader.getResource("serviceAccount.json");
			File file = new File(resource.toURI());
			
			//Parse the service account JSON using Jackson to put it in a Map
			ObjectMapper mapper = new ObjectMapper();
			Map<String, Object> creds = mapper.readValue(file, new TypeReference<Map<String,Object>>(){}); 
			
			//Get the current time in milliseconds
			long nowMs = System.currentTimeMillis();
			
			//System.out.println(nowMs);
			
			//Read in the private RSA key from the service account JSON file
			String privKeyString = ((String) creds.get("private_key")).replace("-----BEGIN PRIVATE KEY-----\n", "");
			privKeyString = privKeyString.replace("-----END PRIVATE KEY-----", "");
			privKeyString = privKeyString.replace("\n", "");
			
			//System.out.println(privKeyString);		
		
			//Use Java security functions to turn the parsed private key into an RSAPrivateKey object
			KeyFactory kf = KeyFactory.getInstance("RSA");
			byte[] byteKey = Base64.getDecoder().decode(privKeyString);
			PKCS8EncodedKeySpec PK8privateKey = new PKCS8EncodedKeySpec(byteKey);
			RSAPrivateKey priv = (RSAPrivateKey) kf.generatePrivate(PK8privateKey);
			
			//System.out.println(priv.toString());
			
			//Build JWT for scopes defined by input string
			String signedJwt = Jwts.builder()
					.setHeaderParam("alg","RS256")
					.setHeaderParam("typ","JWT")
					.setHeaderParam("kid",(String) creds.get("private_key_id"))
					.setIssuer((String) creds.get("client_email"))
					.setAudience("https://oauth2.googleapis.com/token")
					.setExpiration(new Date(nowMs + 3600 * 1000L))
					.setIssuedAt(new Date(nowMs))
					.claim("scope", scopes)
					.signWith(SignatureAlgorithm.RS256, priv)
					.compact();
			
			//System.out.println(signedJwt);
			 
			    
			    result = signedJwt;
		}
		catch(Exception e) {
			result = "ERROR: " + e.getMessage();
		}
		    
		    return result;
	}
}