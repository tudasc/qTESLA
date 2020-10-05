package sctudarmstadt.qtesla.tests;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Locale;

import java.util.concurrent.CyclicBarrier;

import sctudarmstadt.qtesla.java.Common;
import sctudarmstadt.qtesla.java.Logger;
import sctudarmstadt.qtesla.jca.QTESLASignature;
import sctudarmstadt.qtesla.javajca.QTESLAJavaProvider;
//import sctudarmstadt.qtesla.javajca.QTESLASignature;
import sctudarmstadt.qtesla.jca.QTESLAProvider;

public class JavaSecureBenchmark {
	private static Object LOCK = new Object();
	private static String _provi;

	
	private static boolean checkBit (int value, int position) {
		if ((value & (1 << position)) != 0)
		{
		   // The bit was set
			return true;
		}
		return false;
	}

	private static void testKeygenPerformance(int inoruns, int inosignsperrun, KeyPair[] kepas) throws NoSuchAlgorithmException, IOException {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("QTESLA");
		
		//KeyPair peenee = keyGenerator.generateKeyPair();
		
		long startGeneratingKeyPairTimeNano	= System.nanoTime();
		for(int i=0; i<inoruns;i++) {
			//System.out.printf("Start %d\n", i);
			//kepas[i] = peenee;//keyGenerator.generateKeyPair();
			kepas[i] = keyGenerator.generateKeyPair();
			//System.out.printf("End %d\n", i);
		}
		
		long endGeneratingKeyPairTimeNano	= System.nanoTime();
		
		double duration = (endGeneratingKeyPairTimeNano - startGeneratingKeyPairTimeNano) * 1E-6;
		System.out.printf("[qtesla:] Key Generation Time: Total time: %f s, average: %f ms (%f ops/s) \n", 
				duration *1E-3,
				duration/inoruns,
				1.0 / ((duration*1E-3) /(inoruns)));
		
	}
	
	
	
	
	private synchronized static void testPIIIPerformance(int inoruns, int inosignsperrun, int mess_len) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        double[] timeOfGeneratingKeyPair = new double[inoruns];
        double[] timeOfSigning = new double[inoruns * inosignsperrun];
        double[] timeOfVerifying = new double[inoruns * inosignsperrun];
		
		
		// Create the random messages
		byte[][] messages = new byte[inoruns][mess_len];
		for(int i=0; i < inoruns; i++ ) {
			for(int j=0; j<mess_len; j++) {
				int val =  ((((j+51)*19)%7) + ((i+41)*29) * ((j%31 + i + 3) * 13));
				messages[i][j] = (byte) val;
			}
		}
		
		if (Logger.do_qtesla)
		{
		// Test the keypairs
		KeyPair[] kepas = new KeyPair[inoruns];
		try {			
			testKeygenPerformance(inoruns, inosignsperrun, kepas);
		} catch (NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		

		
		
		long startSigningTimeNano	= System.nanoTime();		
		
		Signature siggi = Signature.getInstance("QTESLA");
		
		// Required cast to employ the parallelization for C
		if(_provi.equals("QTESLAProvider")) {
			QTESLASignature tqsiggi = (QTESLASignature)siggi;
			tqsiggi.changeParallelity(Logger.no_of_threads);
			siggi = tqsiggi;
		}
		
		// Sign all messages the number of times which was required
		byte[][][]signatures = new byte[inoruns][inosignsperrun][];
		for(int i=0; i < inoruns; i++ ) {						
			for(int j=0; j < inosignsperrun; j++) {	
			
				siggi.initSign(kepas[i].getPrivate());
				siggi.update(messages[i]);	
				signatures[i][j] = siggi.sign();
				
			    /*synchronized (LOCK) {
			        try {
						LOCK.wait(50);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
			        //System.out.println("Object '" + LOCK + "' is woken after" +
			        //  " waiting for 1 second");
			    }*/			
			}
		}
		
		long endSigningTimeNano	= System.nanoTime();
		
		double duration = (endSigningTimeNano - startSigningTimeNano) * 1E-6;	
		
		System.out.printf("[qtesla:] Signing Time: Total time: %f s, average: %f ms (%f ops/s) \n", 
				duration *1E-3,
				duration/(inoruns*inosignsperrun),
				1.0 / ((duration*1E-3) /(inoruns*inosignsperrun)));
		
		
		// Verify all signatures
		long startVerifyTimeNano	= System.nanoTime();
		
		for(int i=0; i < inoruns; i++ ) {
			siggi.initVerify(kepas[i].getPublic());
			
			
			for(int j=0; j < inosignsperrun; j++) {
				siggi.update(messages[i]);
				
				if(!siggi.verify(signatures[i][j]) )
					System.err.printf ( "%d / %d Signature not verified!", i, j );	
			}
		}
		
		long endVerifyTimeNano	= System.nanoTime();
		duration = (endVerifyTimeNano - startVerifyTimeNano) * 1E-6;
		System.out.printf("[qtesla:] Verify Time: Total time: %f s, average: %f ms (%f ops/s) \n", 
				duration *1E-3,
				duration/(inoruns*inosignsperrun),
				1.0 / ((duration*1E-3) /(inoruns*inosignsperrun)));
		}
		
        // Second run ECDSA
        if (Logger.do_ecdsa)
        {
	        for (int round = 0; round < inoruns; round++) {  
	    		long startGeneratingKeyPairTimeNano	= System.nanoTime();
	    		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
	    		ECGenParameterSpec spec = new ECGenParameterSpec("secp384r1"); //"secp256k1" // brainpoolP384r1 secp384r1
	    		keyPairGenerator.initialize(spec, new SecureRandom());
	    		KeyPair kp = keyPairGenerator.generateKeyPair();
	    		
	    		long endGeneratingKeyPairTimeNano	= System.nanoTime();
	        	for (int signnum = 0; signnum < inosignsperrun; signnum++) {
	        		
	    	        // Sign bytes
	        		long startSigningTimeNano = System.nanoTime();
	        		Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
	        		ecdsaSign.initSign(kp.getPrivate());
	        		ecdsaSign.update(messages[round]);
	    	        byte[] signatureBytes = ecdsaSign.sign();
	        		long endSigningTimeNano = System.nanoTime();
	        		
	      	      //Verify the signature
	    	        long startVerifyingTimeNano1	= System.nanoTime();
	    	        ecdsaSign.initVerify(kp.getPublic());
	    	        ecdsaSign.update(messages[round]);
	    			
	    			if(ecdsaSign.verify(signatureBytes)!=true)
	    				System.out.println("Failure ECDSA verify");
	    			long endVerifyingTimeNano1		= System.nanoTime();
	        		
	    			// 1E-6 converts to Milliseconds
	                timeOfSigning[round*inosignsperrun + signnum] = (endSigningTimeNano - startSigningTimeNano) * 1E-6;
	                timeOfVerifying[round*inosignsperrun + signnum] = (endVerifyingTimeNano1 - startVerifyingTimeNano1) * 1E-6;
	        	}
	        	timeOfGeneratingKeyPair[round] = (endGeneratingKeyPairTimeNano - startGeneratingKeyPairTimeNano) * 1E-6;
	        }
	        
			System.out.printf ("[ECDSA:] Key Generation Time: Total time: %f s, Median number: %f ms, average number: %f ms (%f ops/s) \n", 
					Common.sumNumber(timeOfGeneratingKeyPair)*1E-3, Common.medianNumber(timeOfGeneratingKeyPair), Common.averageNumber(timeOfGeneratingKeyPair),   1.0 / ((Common.sumNumber(timeOfGeneratingKeyPair)*1E-3) /(inoruns)));
			
			System.out.printf ("[ECDSA:] Signing Time: Total time: %f s, Median number: %f ms, average number: %f ms (%f ops/s)\n", 
					Common.sumNumber(timeOfSigning)*1E-3, Common.medianNumber(timeOfSigning), Common.averageNumber(timeOfSigning),  1.0 / ((Common.sumNumber(timeOfSigning)*1E-3) /(inoruns*inosignsperrun)));
			
			System.out.printf ("[ECDSA:] Total time: %f s, Verification Time: Median number: %f ms, average number: %f ms (%f ops/s)\n\n", 
					Common.sumNumber(timeOfVerifying)*1E-3, Common.medianNumber(timeOfVerifying), Common.averageNumber(timeOfVerifying),   1.0 / ((Common.sumNumber(timeOfVerifying)*1E-3) /(inoruns*inosignsperrun)));
			
        } 		
		
     // RSA
     		if(Logger.do_rsa)
     		{
     	        for (int round = 0; round < inoruns; round++) {    
     	        	long startGeneratingKeyPairTimeNano	= System.nanoTime();
     			        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
     			        kpg.initialize(6144); 
     			        KeyPair kp = kpg.generateKeyPair();
     		        long endGeneratingKeyPairTimeNano	= System.nanoTime();
     		        
     	        	for (int signnum = 0; signnum < inosignsperrun; signnum++) {
     	    	        
     	    	        // Sign bytes
     	        		long startSigningTimeNano = System.nanoTime();
     	    	        Signature sig = Signature.getInstance("NONEwithRSA");
     	    	        sig.initSign(kp.getPrivate());
     	    	        sig.update(messages[round]);
     	    	        byte[] signatureBytes = sig.sign();
     	    	        long endSigningTimeNano = System.nanoTime();
     	    	        
     	    	      //Verify the signature
     	    	        long startVerifyingTimeNano1	= System.nanoTime();
     	    			sig.initVerify(kp.getPublic());
     	    			sig.update(messages[round]);
     	    			
     	    			if(sig.verify(signatureBytes)!=true)
     	    				System.out.println("Failure RSA verify");
     	    			long endVerifyingTimeNano1		= System.nanoTime();
     	    			
     	    			// 1E-6 converts to Milliseconds
     	                timeOfSigning[round*inosignsperrun + signnum] = (endSigningTimeNano - startSigningTimeNano) * 1E-6;
     	                timeOfVerifying[round*inosignsperrun + signnum] = (endVerifyingTimeNano1 - startVerifyingTimeNano1) * 1E-6;
     	            }
     	            timeOfGeneratingKeyPair[round] = (endGeneratingKeyPairTimeNano - startGeneratingKeyPairTimeNano) * 1E-6;
     	        }      
     	   
     	   
     			System.out.printf ("[RSA:] Key Generation Time: Total time: %f s, Median number: %f ms, average number: %f ms (%f ops/s) \n", 
     					Common.sumNumber(timeOfGeneratingKeyPair)*1E-3, Common.medianNumber(timeOfGeneratingKeyPair), Common.averageNumber(timeOfGeneratingKeyPair),   1.0 / ((Common.sumNumber(timeOfGeneratingKeyPair)*1E-3) /(inoruns)));
     			
     			System.out.printf ("[RSA:] Signing Time: Total time: %f s, Median number: %f ms, average number: %f ms (%f ops/s)\n", 
     					Common.sumNumber(timeOfSigning)*1E-3, Common.medianNumber(timeOfSigning), Common.averageNumber(timeOfSigning),  1.0 / ((Common.sumNumber(timeOfSigning)*1E-3) /(inoruns*inosignsperrun)));
     			
     			System.out.printf ("[RSA:] Total time: %f s, Verification Time: Median number: %f ms, average number: %f ms (%f ops/s)\n\n", 
     					Common.sumNumber(timeOfVerifying)*1E-3, Common.medianNumber(timeOfVerifying), Common.averageNumber(timeOfVerifying),   1.0 / ((Common.sumNumber(timeOfVerifying)*1E-3) /(inoruns*inosignsperrun)));
     		}		
        
        
		
		return;
	}
	
	private static void loadSecurityProvider() {
		// Add the security provider of QTESLA
		if(_provi.equals("QTESLAProvider")) {
			Security.addProvider(new QTESLAProvider());	
		}
		
		else if(_provi.equals("QTESLAJavaProvider")) {
			Security.addProvider(new QTESLAJavaProvider());	
		}
		
		else {
			System.err.println("Given Provider " + _provi + " not recognized.");
			Security.addProvider(new QTESLAProvider());	
		}
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
		long startGeneratingKeyPairTimeNano	= System.nanoTime();
		
		Locale.setDefault(Locale.ENGLISH);
		
		// Check if user deployed a value for the number of runs
        int inoruns;
        // Check if user deployed a value for the number of runs
        try {
            inoruns = Integer.parseInt(args[0]);
        }
        catch (NumberFormatException e)
        {
            inoruns = 15;
        }	
        
        // Check if user passed a number of signs per run
        int inosignsperrun;
        // Check if user deployed a value for the number of runs
        try {
            inosignsperrun = Integer.parseInt(args[1]);
        }
        catch (NumberFormatException e)
        {
            inosignsperrun = 1;
        }        
        
        // Tests to perform
        // Check which tests should be performed, default only qtesla
        try {
            int val = Integer.parseInt(args[2]);
            
			Logger.do_rsa=checkBit(val,2);
			Logger.do_ecdsa=checkBit(val,1);
			Logger.do_qtesla=checkBit(val,0);
        }
        catch (Exception e)
        {
        	Logger.no_of_threads = 1;
        	Logger.do_qtesla = true;
        	Logger.do_ecdsa = false;
        	Logger.do_rsa = false;
        }  
        
        // Degree of parallelism
        // Check if user deployed a value for the number of runs
        try {
            Logger.no_of_threads = Integer.parseInt(args[3]);
        }
        catch (NumberFormatException e)
        {
        	Logger.no_of_threads = 1;
        }  
        
        // Get the security_provider
        try {
        	String p = args[4];
        	_provi = p;
        	System.err.println(_provi);
        }
        
        catch (Exception e) {
        	_provi = "QTESLAProvider";
        }
       
        System.out.printf("Performing %d runs @ %d singings with %s provider.\n ", inoruns, inosignsperrun, _provi);

        loadSecurityProvider();
        
		testPIIIPerformance (inoruns, inosignsperrun, 280);		
		long endGeneratingKeyPairTimeNano	= System.nanoTime();
		
		double duration=(endGeneratingKeyPairTimeNano-startGeneratingKeyPairTimeNano)*1E-9;

		System.out.printf("Overall program time: %f s.\n", duration);
		
	}
}
