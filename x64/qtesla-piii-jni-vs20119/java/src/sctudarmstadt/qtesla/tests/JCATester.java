package sctudarmstadt.qtesla.tests;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Enumeration;

//import sctudarmstadt.qtesla.jca.QTESLAProvider;
import sctudarmstadt.qtesla.javajca.QTESLAJavaProvider;
import sctudarmstadt.qtesla.jca.QTESLAProvider;

public class JCATester {
	private static void removeProviders() {
		   try {
		        Provider p[] = Security.getProviders();
		        for (int i = 0; i < p.length; i++) {
		        	String[] expected1 = p[i].toString().split(" ");	
		        	if(expected1[0].compareTo("SUN") != 0)
		        		Security.removeProvider(expected1[0]);
		        }
		      } catch (Exception e) {
		        System.out.println(e);
		      }		
	}
	
	private static void showAllProviders() {
		   try {
		        Provider p[] = Security.getProviders();
		        for (int i = 0; i < p.length; i++) {
		            System.out.println("Successfully found provider: " + p[i]);
		            for (Enumeration<Object> e = p[i].keys(); e.hasMoreElements();)
		                System.out.println("\t" + e.nextElement());
		        }
		      } catch (Exception e) {
		        System.out.println(e);
		      }
	}
	
	public static boolean checkBit (int value, int position) {
		if ((value & (1 << position)) != 0)
		{
		   // The bit was set
			return true;
		}
		return false;
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		// Make a Key with Java
		   // Test 1A other OS
		
				// Add the security provider of QTESLA
			   /*System.out.println("Add QTESLAProvider to Security.");
				Security.addProvider(new QTESLAJavaProvider());
				System.out.println("");

			   KeyPairGenerator keyGenerator_java = KeyPairGenerator.getInstance("QTESLA");
			   KeyPair kepa = keyGenerator_java.generateKeyPair();*/
		
		
		
		System.out.println("Running with " + System.getProperty("java.runtime.name") + " " + System.getProperty("java.version"));
		System.out.println("");
		
		System.out.println("Remove all providers from Security for the run.");
		removeProviders();		   
	
		// Add the security provider of QTESLA
		System.out.println("Add QTESLAProvider to Security.");
		Security.addProvider(new QTESLAProvider());
		System.out.println("");			

  
	   // Test Keygen
	   System.out.println("Try to generate KeyPairGenerator.getInstance(\"QTESLA\")");
	   KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("QTESLA");
	   System.out.println("Success");
	   System.out.println("");
	   
	   System.out.println("Try to generate a KeyPair");
	   KeyPair kepa = keyGenerator.generateKeyPair();
	   System.out.println("Success");
	   System.out.println("");
	   
	   //String keystr = Base64.getEncoder().encodeToString(kepa.getPrivate().getEncoded());	
	   //System.out.println(keystr);

	   
	   // Test Sign
	   removeProviders();	
	   Security.addProvider(new QTESLAProvider());
	   String message = "Hallo Anna, hoffe dein Paper wird super.";
	   Signature siggi = Signature.getInstance("QTESLA");
	   
	   siggi.initSign(kepa.getPrivate());
	   siggi.update(message.getBytes(StandardCharsets.UTF_8));	 	   
	   System.out.println("Signing Message: " + message);
	   byte[] signature = siggi.sign();		   
	   String sigstr = Base64.getEncoder().encodeToString(signature);
	   System.out.println(sigstr);		      

	   // Sign with Java
	   removeProviders();
	   Security.addProvider(new QTESLAJavaProvider());	   
	   siggi = Signature.getInstance("QTESLA");
	   siggi.initSign(kepa.getPrivate());
	   siggi.update(message.getBytes(StandardCharsets.UTF_8));
	   signature = siggi.sign();	
	   sigstr = Base64.getEncoder().encodeToString(signature);	
	   System.out.println(sigstr);
	   System.out.println("Message was successfully signed with length " + signature.length + " and algorithm: " + siggi.getAlgorithm());
	   removeProviders();
	   Security.addProvider(new QTESLAProvider());
	   
	   // Verify tests
	   // Different Language 1A other OS
	   System.out.println("[Verifying Test #1A]");
	   System.out.println("Checking Message with Java implementation");
	   removeProviders();
	   Security.addProvider(new QTESLAJavaProvider());
	   
	   Signature c_siggi = Signature.getInstance("QTESLA");
	   c_siggi.initVerify(kepa.getPublic());
	   
	   byte[] signatureBytes = Base64.getDecoder().decode(sigstr);
	   c_siggi.update(message.getBytes(StandardCharsets.UTF_8));
	   
	   boolean is_correct = c_siggi.verify(signatureBytes);   
	   if(is_correct) {
		   System.out.println("As expected, the message is verified");
	   }
	   else {
		   System.out.println("Unexpectedly, the message is not verified");
	   }
	   System.out.println("");
	   removeProviders();
	   Security.addProvider(new QTESLAProvider());	   
	   Signature pub_siggi = Signature.getInstance("QTESLA");
	   pub_siggi.initVerify(kepa.getPublic());	 
	   
	   // Test Verify1: This should work
	   System.out.println("[Verifying Test #1]");
	   System.out.println("Checking Message: >>" + message + "<<");
	   signatureBytes = Base64.getDecoder().decode(sigstr);
	   pub_siggi.update(message.getBytes(StandardCharsets.UTF_8));
	   
	   is_correct = pub_siggi.verify(signatureBytes);   
	   if(is_correct) {
		   System.out.println("As expected, the message is verified");
	   }
	   else {
		   System.out.println("Unexpectedly, the message is not verified");
	   }
	   System.out.println("");	   

	
	   

	   // Test Verify2: Corrupt the signature
	   System.out.println("[Verifying Test #2]");
	   System.out.println("Checking Signature corrupted at position [5] to '33'");
	   byte[] signatureBytes_corrupted = signatureBytes;
	   signatureBytes_corrupted[5] = 33;
	   pub_siggi.update(message.getBytes(StandardCharsets.UTF_8));
	   is_correct = pub_siggi.verify(signatureBytes);
	   if(!is_correct) {
		   System.out.println("As expected, the message is not verified");
	   }
	   else {
		   System.out.println("Unexpectedly, the message is verified");
	   }	   
	   System.out.println("");
	   
	   // Test Verify3: Test another message of equal length
	   System.out.println("[Verifying Test #3]");
	   String message_corrupted = "Hallo Anna, hoffe dein Paper wird bloed.";
	   System.out.println("Checking corrupted Message of equal length: >>" + message_corrupted + "<<");
	   pub_siggi.update(message_corrupted.getBytes(StandardCharsets.UTF_8));
	   is_correct = pub_siggi.verify(signatureBytes);
	   if(!is_correct) {
		   System.out.println("As expected, the message is not verified");
	   }
	   else {
		   System.out.println("Unexpectedly, the message is verified");
	   }
	   System.out.println("");	
	   
	   
	   // Test Verify4: Test another message of unequal length
	   System.out.println("[Verifying Test #4]");
	   String message_corrupted2 = "Hallo Berta, hoffe deine Dissertation wird klasse.";
	   System.out.println("Checking corrupted Message of unequal length: >>" + message_corrupted2 + "<<");
	   pub_siggi.update(message_corrupted2.getBytes(StandardCharsets.UTF_8));
	   is_correct = pub_siggi.verify(signatureBytes);
	   if(!is_correct) {
		   System.out.println("As expected, the message is not verified");
	   }
	   else {
		   System.out.println("Unexpectedly, the message is verified");
	   }
	   System.out.println("");
	   
	   
	   // Test Verify5: Test wrong public key
	   System.out.println("[Verifying Test #5]");
	   System.out.println("Checking to verify with wrong PublicKey");
	   KeyPair kepa2 = keyGenerator.generateKeyPair();
	   pub_siggi.initVerify(kepa2.getPublic());
	   pub_siggi.update(message.getBytes(StandardCharsets.UTF_8));
	   is_correct = pub_siggi.verify(signatureBytes);
	   if(!is_correct) {
		   System.out.println("As expected, the message is not verified");
	   }
	   else {
		   System.out.println("Unexpectedly, the message is verified");
	   }
	   System.out.println("");
	   
	   // Verify tests
	   Signature pub_siggi2 = Signature.getInstance("QTESLA");
	   pub_siggi2.initVerify(kepa.getPublic());
	   
	   // Test Verify6: This should work
	   System.out.println("[Verifying Test #6]");
	   System.out.println("Checking Message: >>" + message + "<< with a new Instance of Signature with right PublicKey");
	   signatureBytes = Base64.getDecoder().decode(sigstr);
	   pub_siggi2.update(message.getBytes(StandardCharsets.UTF_8));
	   
	   is_correct = pub_siggi2.verify(signatureBytes);   
	   if(is_correct) {
		   System.out.println("As expected, the message is verified");
	   }
	   else {
		   System.out.println("Unexpectedly, the message is not verified");
	   }
	   System.out.println("");
	}
}
