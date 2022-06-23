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
	public static String createJWT(String privateKeyId, String privateKey, String issuer, String user, String scopes, String audience){
		String result = "";
		try {
			
			//System.out.println("START");
			
			//System.out.println("User: " + user);
			
			//Get the current time in milliseconds
			long nowMs = System.currentTimeMillis();
			
			//System.out.println("Now in Milliseconds: " + nowMs);
			//System.out.println("Original key string: " + privateKey);
				
			//Use Java security functions to turn the parsed private key into an RSAPrivateKey object
			KeyFactory kf = KeyFactory.getInstance("RSA");
			byte[] byteKey = Base64.getDecoder().decode(privateKey);
			PKCS8EncodedKeySpec PK8privateKey = new PKCS8EncodedKeySpec(byteKey);
			RSAPrivateKey priv = (RSAPrivateKey) kf.generatePrivate(PK8privateKey);
			
			//System.out.println("RSAPrivateKey: " + priv.toString());
			
			//Build JWT
			String signedJwt;
			//If user is given create token w/ subject for impersonation
			if(user != null || !(user.equals(""))) {
				signedJwt = Jwts.builder()
						.setHeaderParam("alg","RS256")
						.setHeaderParam("typ","JWT")
						.setHeaderParam("kid",privateKeyId)
						.setIssuer(issuer)
						.setSubject(user)
						.setAudience(audience)
						.setExpiration(new Date(nowMs + 3600 * 1000L))
						.setIssuedAt(new Date(nowMs))
						.claim("scope", scopes)
						.signWith(SignatureAlgorithm.RS256, priv)
						.compact();
			}
			//If user is not given create token w/o subject
			else {
				signedJwt = Jwts.builder()
						.setHeaderParam("alg","RS256")
						.setHeaderParam("typ","JWT")
						.setHeaderParam("kid",privateKeyId)
						.setIssuer(issuer)
						.setAudience(audience)
						.setExpiration(new Date(nowMs + 3600 * 1000L))
						.setIssuedAt(new Date(nowMs))
						.claim("scope", scopes)
						.signWith(SignatureAlgorithm.RS256, priv)
						.compact();
			}
			
			
			//System.out.println("Final JWT: " + signedJwt);
			 
				result = signedJwt;
		}
		catch(Exception e) {
			result = "ERROR: " + e.getMessage();
		}
		    
		    return result;
	}
}