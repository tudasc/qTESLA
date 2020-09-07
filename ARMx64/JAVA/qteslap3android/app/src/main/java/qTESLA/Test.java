package qTESLA;

import android.icu.text.DecimalFormat;
import android.os.Build;
import android.support.annotation.RequiresApi;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class Test {

    static SecureRandom secureRandom = new SecureRandom();
    static short shortNumber = (short) 0xCCDD;
    static int integerNumber = 0xCCDDEEFF;
    static long longNumber = 0xCCDDEEFFAABB0011L;

    static byte[] byteArray = {

            (byte) 0xAB, (byte) 0xBC, (byte) 0xCD, (byte) 0xDE,
            (byte) 0xEF, (byte) 0xF0, (byte) 0x01, (byte) 0x12,
            (byte) 0x23, (byte) 0x34, (byte) 0x45, (byte) 0x56,
            (byte) 0x67, (byte) 0x78, (byte) 0x89, (byte) 0x9A

    };

    static byte[] seed = {

            (byte) 0x12, (byte) 0x23, (byte) 0x34, (byte) 0x45, (byte) 0x56, (byte) 0x67, (byte) 0x78, (byte) 0x89, // 1
            (byte) 0x9A, (byte) 0xAB, (byte) 0xBC, (byte) 0xCD, (byte) 0xDE, (byte) 0xEF, (byte) 0xF1, (byte) 0x13, // 2
            (byte) 0x24, (byte) 0x35, (byte) 0x46, (byte) 0x57, (byte) 0x68, (byte) 0x79, (byte) 0x8A, (byte) 0x9B, // 3
            (byte) 0xAC, (byte) 0xBD, (byte) 0xCE, (byte) 0xDF, (byte) 0xE1, (byte) 0xF2, (byte) 0x14, (byte) 0x25, // 4
            (byte) 0x36, (byte) 0x47, (byte) 0x58, (byte) 0x69, (byte) 0x7A, (byte) 0x8B, (byte) 0x9C, (byte) 0xAD, // 5
            (byte) 0xBE, (byte) 0xCF, (byte) 0xD1, (byte) 0xE2, (byte) 0xF3, (byte) 0x15, (byte) 0x26, (byte) 0x37, // 6
            (byte) 0x48, (byte) 0x59, (byte) 0x6A, (byte) 0x7B, (byte) 0x8C, (byte) 0x9D, (byte) 0xAE, (byte) 0xBF, // 7
            (byte) 0xC1, (byte) 0xD2, (byte) 0xE3, (byte) 0xF4, (byte) 0x16, (byte) 0x27, (byte) 0x38, (byte) 0x49, // 8
            (byte) 0x5A, (byte) 0x6B, (byte) 0x7C, (byte) 0x8D, (byte) 0x9E, (byte) 0xAF, (byte) 0xB1, (byte) 0xC2, // 9
            (byte) 0xD3, (byte) 0xE4, (byte) 0xF5, (byte) 0x17, (byte) 0x28, (byte) 0x39, (byte) 0x4A, (byte) 0x5B, // 10
            (byte) 0x6C, (byte) 0x7D, (byte) 0x8E, (byte) 0x9F, (byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4, // 11
            (byte) 0xE5, (byte) 0xF6, (byte) 0x18, (byte) 0x29, (byte) 0x3A, (byte) 0x4B, (byte) 0x5C, (byte) 0x6D, // 12
            (byte) 0x7E, (byte) 0x8F, (byte) 0x91, (byte) 0xA2, (byte) 0xB3, (byte) 0xC4, (byte) 0xD5, (byte) 0xE6, // 13
            (byte) 0xF7, (byte) 0x19, (byte) 0x2A, (byte) 0x3B, (byte) 0x4C, (byte) 0x5D, (byte) 0x6E, (byte) 0x7F, // 14
            (byte) 0x81, (byte) 0x92, (byte) 0xA3, (byte) 0xB4, (byte) 0xC5, (byte) 0xD6, (byte) 0xE7, (byte) 0xF8, // 15
            (byte) 0x1A, (byte) 0x2B, (byte) 0x3C, (byte) 0x4D, (byte) 0x5E, (byte) 0x6F, (byte) 0x71, (byte) 0x82, // 16

    };

    public static void mainTest (int runs, int signsperrun)

            throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, ShortBufferException, SignatureException, InterruptedException {
        testGenerateKeyPairSigningVerifyingPIII (runs, signsperrun);
    }


    /* Test for Generation of the Key Pair, Signing and Verifying for Provably Secure qTESLA Security Category 3 */

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void testGenerateKeyPairSigningVerifyingPIII (int runs, int signsperrun)

            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException, SignatureException, InterruptedException {

        System.out.println ("Test for Generation of the Key Pair for Provably-Secure qTESLA Security Category 3\n");
        long startBenchmarkNano	= System.nanoTime();
        QTESLA qTESLA		= new QTESLA ("qTESLA-P-III");
        byte[] publicKey	= new byte[qTESLA.getQTESLAParameter().publicKeySize];
        byte[] privateKey	= new byte[qTESLA.getQTESLAParameter().privateKeySize];
        byte[] seed			= new byte[48];
        String seedString 	= "64335BF29E5DE62842C941766BA129B0643B5E7121CA26CFC190EC7DC3543830557FDD5C03CF123A456D48EFEA43C868";

        // Create a stream to hold the output
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        // IMPORTANT: Save the old System.out!
        PrintStream old = System.out;
        // Tell Java to use your special stream
        System.setOut(ps);

        //System.out.printf ("\nCRYPTO_PUBLICKEY_BYTES: %d\n",  qTESLA.getQTESLAParameter().publicKeySize);
        //System.out.printf ("CRYPTO_SECRETKEY_BYTES: %d\n",  qTESLA.getQTESLAParameter().privateKeySize);
        //System.out.printf ("CRYPTO_SIGNATURE_BYTES: %d\n",  qTESLA.getQTESLAParameter().signatureSize);




        int timeOfTest = runs;

        double[] timeOfGeneratingKeyPair = new double[timeOfTest];
        double[] timeOfSigning = new double[timeOfTest * signsperrun];
        double[] timeOfVerifying = new double[timeOfTest * signsperrun];

        seed = Common.hexadecimalStringToByteArray (seedString);
        Logger.seed = seed;
        int messlen = qTESLA.getQTESLAParameter().messageLength;

        // Create Random Messages
        qTESLA.getRandomNumberGenerator().initiateRandomByte (seed, null, 256);
        byte[][] messageInput = new byte[timeOfTest][messlen];
        for (int round = 0; round < timeOfTest; round++) {
            //SecureRandom.getInstanceStrong().nextBytes(messageInput[round]);
            for(int ii=0; ii<messlen; ii++) {
                int val =  ((((ii+51)*19)%7) + ((round+41)*29) * ((ii%31 + round + 3) * 13));
                messageInput[round][ii] = (byte) ((ii + 33) % 127 ) ;
            }
        }

        // qtesla Suite
        if(Logger.test_qtesla) {
            for (int round = 0; round < timeOfTest; round++) {

                qTESLA.getRandomNumberGenerator().initiateRandomByte(seed, null, 256);

                long startGeneratingKeyPairTimeNano = System.nanoTime();
                qTESLA.generateKeyPair_MB (publicKey, privateKey, secureRandom);
                long endGeneratingKeyPairTimeNano = System.nanoTime();

                int[] signatureLength = new int[1];
                int[] messageLength = new int[1];
                byte[] signature = new byte[qTESLA.getQTESLAParameter().signatureSize + messlen];

                for (int signnum = 0; signnum < signsperrun; signnum++) {
                    long startSigningTimeNano = System.nanoTime();
                    qTESLA.signPParallel(signature, 0, signatureLength, messageInput[round], 0, messlen, privateKey, secureRandom);
                    long endSigningTimeNano = System.nanoTime();

                    int valid;
                    int response;
                    byte[] messageOutput = new byte[qTESLA.getQTESLAParameter().signatureSize + messlen];

                    // System.out.println ("Test for Verifying for Provably Secure qTESLA Security Category 3\n");

                    long startVerifyingTimeNano1 = System.nanoTime();
                    valid = qTESLA.verify_MB(messageOutput, 0, messageLength, signature, 0, signatureLength[0], publicKey);
                    long endVerifyingTimeNano1 = System.nanoTime();

                    if (valid != 0) {

                        System.out.println("Signature Verification Failed with " + valid + "\n");

                    } else if (messageLength[0] != messlen) {

                        System.out.println("Verifying Returned BAD Message Length with " + messageLength[0] + " Bytes\n");

                    }

                    for (int i = 0; i < messageLength[0]; i++) {

                        if (messageInput[round][i] != messageOutput[i]) {

                            System.out.println("Verifying Returned BAD Message Value with Message Input " + messageInput[round][i] + "and Message Output " + messageOutput[i] + "\n");
                            break;

                        }

                    }

                    signature[secureRandom.nextInt(32) % (qTESLA.getQTESLAParameter().signatureSize + qTESLA.getQTESLAParameter().messageLength)] ^= 1;

                    long startVerifyingTimeNano2 = System.nanoTime();
                    response = qTESLA.verify_MB(messageOutput, 0, messageLength, signature, 0, signatureLength[0], publicKey);
                    long endVerifyingTimeNano2 = System.nanoTime();

                    // 1E-6 converts to Milliseconds
                    timeOfSigning[round*signsperrun + signnum] = (endSigningTimeNano - startSigningTimeNano) * 1E-6;
                    timeOfVerifying[round*signsperrun + signnum] = (endVerifyingTimeNano1 - startVerifyingTimeNano1) * 1E-6;
                     }
                timeOfGeneratingKeyPair[round] = (endGeneratingKeyPairTimeNano - startGeneratingKeyPairTimeNano) * 1E-6;
            }
            long endBenchmarkNano = System.nanoTime();

            System.out.printf ("[qtesla:] Key Generation Time: Total time: %.2f s, Median number: %.2f ms, average number: %.2f ms (%.2f ops/s) \n",
                    Common.sumNumber(timeOfGeneratingKeyPair)*1E-3, Common.medianNumber(timeOfGeneratingKeyPair), Common.averageNumber(timeOfGeneratingKeyPair),   1.0 / ((Common.sumNumber(timeOfGeneratingKeyPair)*1E-3) /(timeOfTest)));

            System.out.printf ("[qtesla:] Signing Time: Total time: %.2f s, Median number: %.2f ms, average number: %.2f ms (%.2f ops/s)\n",
                    Common.sumNumber(timeOfSigning)*1E-3, Common.medianNumber(timeOfSigning), Common.averageNumber(timeOfSigning), 1.0 / ((Common.sumNumber(timeOfSigning)*1E-3)/(timeOfTest*signsperrun)),
                    1.0 / ((Common.sumNumber(timeOfSigning)*1E-3) / (timeOfTest*signsperrun)));

            System.out.printf ("[qtesla:] Total time: %.2f s, Verification Time: Median number: %.2f ms, average number: %.2f ms (%.2f ops/s) \n\n",
                    Common.sumNumber(timeOfVerifying)*1E-3, Common.medianNumber(timeOfVerifying), Common.averageNumber(timeOfVerifying),   1.0 / ((Common.sumNumber(timeOfVerifying)*1E-3) /(timeOfTest*signsperrun)));

        }

        // ECDSA
        if (Logger.test_ecdsa) {
            timeOfGeneratingKeyPair = new double[timeOfTest];
            timeOfSigning = new double[timeOfTest * signsperrun];
            timeOfVerifying = new double[timeOfTest * signsperrun];
            for (int round = 0; round < timeOfTest; round++) {
                long startGeneratingKeyPairTimeNano = System.nanoTime();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec spec = new ECGenParameterSpec("secp384r1"); /*"secp256k1"*/
                keyPairGenerator.initialize(spec, new SecureRandom());
                KeyPair kp = keyPairGenerator.generateKeyPair();
                long endGeneratingKeyPairTimeNano = System.nanoTime();

                for (int signnum = 0; signnum < signsperrun; signnum++) {

                    // Sign bytes
                    long startSigningTimeNano = System.nanoTime();
                    Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
                    ecdsaSign.initSign(kp.getPrivate());
                    ecdsaSign.update(messageInput[round]);
                    byte[] signatureBytes = ecdsaSign.sign();
                    long endSigningTimeNano = System.nanoTime();

                    //Verify the signature
                    long startVerifyingTimeNano1 = System.nanoTime();
                    ecdsaSign.initVerify(kp.getPublic());
                    ecdsaSign.update(messageInput[round]);

                    //System.out.printf("%d %d\n",round,signnum);

                    if (ecdsaSign.verify(signatureBytes) != true)
                        System.out.println("Failure ECDSA verify");
                    long endVerifyingTimeNano1 = System.nanoTime();

                    // 1E-6 converts to Milliseconds
                    timeOfSigning[round * signsperrun + signnum] = (endSigningTimeNano - startSigningTimeNano) * 1E-6;
                    timeOfVerifying[round * signsperrun + signnum] = (endVerifyingTimeNano1 - startVerifyingTimeNano1) * 1E-6;
                }
                timeOfGeneratingKeyPair[round] = (endGeneratingKeyPairTimeNano - startGeneratingKeyPairTimeNano) * 1E-6;
            }

            System.out.printf("[ECDSA:] Key Generation Time: Total time: %.2f s, Median number: %.2f ms, average number: %.2f ms (%.2f ops/s) \n",
                    Common.sumNumber(timeOfGeneratingKeyPair) * 1E-3, Common.medianNumber(timeOfGeneratingKeyPair), Common.averageNumber(timeOfGeneratingKeyPair), 1.0 / ((Common.sumNumber(timeOfGeneratingKeyPair) * 1E-3) / (timeOfTest)));

            System.out.printf("[ECDSA:] Signing Time: Total time: %.2f s, Median number: %.2f ms, average number: %.2f ms (%.2f ops/s)\n",
                    Common.sumNumber(timeOfSigning) * 1E-3, Common.medianNumber(timeOfSigning), Common.averageNumber(timeOfSigning), 1.0 / ((Common.sumNumber(timeOfSigning) * 1E-3) / (timeOfTest * signsperrun)));

            System.out.printf("[ECDSA:] Total time: %.2f s, Verification Time: Median number: %.2f ms, average number: %.2f ms (%.2f ops/s)\n\n",
                    Common.sumNumber(timeOfVerifying) * 1E-3, Common.medianNumber(timeOfVerifying), Common.averageNumber(timeOfVerifying), 1.0 / ((Common.sumNumber(timeOfVerifying) * 1E-3) / (timeOfTest * signsperrun)));

        }

        // RSA
        if(Logger.test_rsa) {
            timeOfGeneratingKeyPair = new double[timeOfTest];
            timeOfSigning = new double[timeOfTest * signsperrun];
            timeOfVerifying = new double[timeOfTest * signsperrun];
            for (int round = 0; round < timeOfTest; round++) {
                long startGeneratingKeyPairTimeNano = System.nanoTime();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(Logger.rsa_bitlen);
                KeyPair kp = kpg.generateKeyPair();
                long endGeneratingKeyPairTimeNano = System.nanoTime();

                for (int signnum = 0; signnum < signsperrun; signnum++) {

                    // Sign bytes
                    long startSigningTimeNano = System.nanoTime();
                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initSign(kp.getPrivate());
                    sig.update(messageInput[round]);
                    byte[] signatureBytes = sig.sign();
                    long endSigningTimeNano = System.nanoTime();

                    //Verify the signature
                    long startVerifyingTimeNano1 = System.nanoTime();
                    sig.initVerify(kp.getPublic());
                    sig.update(messageInput[round]);

                    if (sig.verify(signatureBytes) != true)
                        System.out.println("Failure RSA verify");
                    long endVerifyingTimeNano1 = System.nanoTime();

                    // 1E-6 converts to Milliseconds
                    timeOfSigning[round * signsperrun + signnum] = (endSigningTimeNano - startSigningTimeNano) * 1E-6;
                    timeOfVerifying[round * signsperrun + signnum] = (endVerifyingTimeNano1 - startVerifyingTimeNano1) * 1E-6;
                }
                timeOfGeneratingKeyPair[round] = (endGeneratingKeyPairTimeNano - startGeneratingKeyPairTimeNano) * 1E-6;
            }

            System.out.printf("[RSA-%d:] Key Generation Time: Total time: %.2f s, Median number: %.2f ms, average number: %.2f ms (%.2f ops/s) \n",
                    Logger.rsa_bitlen, Common.sumNumber(timeOfGeneratingKeyPair) * 1E-3, Common.medianNumber(timeOfGeneratingKeyPair), Common.averageNumber(timeOfGeneratingKeyPair), 1.0 / ((Common.sumNumber(timeOfGeneratingKeyPair) * 1E-3) / (timeOfTest)));

            System.out.printf("[RSA-%d:] Signing Time: Total time: %.2f s, Median number: %.2f ms, average number: %.2f ms (%.2f ops/s)\n",
                    Logger.rsa_bitlen, Common.sumNumber(timeOfSigning) * 1E-3, Common.medianNumber(timeOfSigning), Common.averageNumber(timeOfSigning), 1.0 / ((Common.sumNumber(timeOfSigning) * 1E-3) / (timeOfTest * signsperrun)));

            System.out.printf("[RSA-%d:] Total time: %.2f s, Verification Time: Median number: %.2f ms, average number: %.2f ms (%.2f ops/s)\n\n",
                    Logger.rsa_bitlen, Common.sumNumber(timeOfVerifying) * 1E-3, Common.medianNumber(timeOfVerifying), Common.averageNumber(timeOfVerifying), 1.0 / ((Common.sumNumber(timeOfVerifying) * 1E-3) / (timeOfTest * signsperrun)));

        }


        // Put things back
        System.out.flush();
        System.setOut(old);
        // Show what happened
        //System.out.println("Here: " + baos.toString());
        Logger.addMessage(baos.toString());

    }
}