package trialproject;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;


public class PGPEncrypt 
{
	public static void encryptMyFile(
			String inputFilePath,
			String outputFilePath,
			PGPPublicKey[] recipientPublicKeys,
			boolean armor
			) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		//FileOutputStream out = new FileOutputStream(outputFilePath);
		OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));
		if(armor)
		{
			out = new ArmoredOutputStream(out);        
		}
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
				PGPCompressedData.ZIP);

		PGPUtil.writeFileToLiteralData(
				comData.open(bOut),
				PGPLiteralData.BINARY,
				new File(inputFilePath));

		comData.close();

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(
						PGPEncryptedData.CAST5)
				.setWithIntegrityPacket(true)
				.setSecureRandom(
						new SecureRandom())
				.setProvider("BC"));

		for (PGPPublicKey publicKey : recipientPublicKeys) {
			cPk.addMethod(
					new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
					.setProvider("BC"));
		}

		byte[] bytes = bOut.toByteArray();

		OutputStream cOut = cPk.open(out, bytes.length);

		cOut.write(bytes);

		cOut.close();

		out.close();
	}
	public static void encryptFile(
			String inputFilePath,
			String outputFilePath,
			String compositePublicKeyPath,
			boolean armor
			) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(new FileInputStream(compositePublicKeyPath)), new JcaKeyFingerprintCalculator());        

		System.out.println( "Loaded Pub Key" );
		Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
		System.out.println( "Read Pub KeyRing" );

		// Add all recipient public keys to an array
		PGPPublicKey[] recipientPublicKeys = new PGPPublicKey[pgpPublicKeyRingCollection.size()];
		int i = 0;
		while (keyRingIterator.hasNext()) {
			PGPPublicKeyRing keyRing = keyRingIterator.next();
			recipientPublicKeys[i++] = keyRing.getPublicKey();
			System.out.println( "Iterate Pub Key" );
		}
		//FileOutputStream out = new FileOutputStream(outputFilePath);
		OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));
		if(armor)
		{
			out = new ArmoredOutputStream(out);        
		}
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
				PGPCompressedData.ZIP);

		PGPUtil.writeFileToLiteralData(
				comData.open(bOut),
				PGPLiteralData.BINARY,
				new File(inputFilePath));

		comData.close();

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(
						PGPEncryptedData.CAST5)
				.setWithIntegrityPacket(true)
				.setSecureRandom(
						new SecureRandom())
				.setProvider("BC"));

		for (PGPPublicKey publicKey : recipientPublicKeys) {
			cPk.addMethod(
					new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
					.setProvider("BC"));
		}

		byte[] bytes = bOut.toByteArray();

		OutputStream cOut = cPk.open(out, bytes.length);

		cOut.write(bytes);

		cOut.close();

		out.close();
		
		System.out.println( "Encryption Process Completed" );
	}
	
	public static ByteArrayInputStream encryptFile1(
			String inputFilePath,
			String outputFilePath,
			String compositePublicKeyPath,
			boolean armor
			) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(new FileInputStream(compositePublicKeyPath)), new JcaKeyFingerprintCalculator());        

		System.out.println( "Loaded Pub Key" );
		Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
		System.out.println( "Read Pub KeyRing" );

		// Add all recipient public keys to an array
		PGPPublicKey[] recipientPublicKeys = new PGPPublicKey[pgpPublicKeyRingCollection.size()];
		int i = 0;
		while (keyRingIterator.hasNext()) {
			PGPPublicKeyRing keyRing = keyRingIterator.next();
			recipientPublicKeys[i++] = keyRing.getPublicKey();
			System.out.println( "Iterate Pub Key" );
		}
		//FileOutputStream out = new FileOutputStream(outputFilePath);
		
		/*
		OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));
		if(armor)
		{
			out = new ArmoredOutputStream(out);        
		}
		*/
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
				PGPCompressedData.ZIP);

		PGPUtil.writeFileToLiteralData(
				comData.open(bOut),
				PGPLiteralData.BINARY,
				new File(inputFilePath));

		comData.close();

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(
						PGPEncryptedData.CAST5)
				.setWithIntegrityPacket(true)
				.setSecureRandom(
						new SecureRandom())
				.setProvider("BC"));

		for (PGPPublicKey publicKey : recipientPublicKeys) {
			cPk.addMethod(
					new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
					.setProvider("BC"));
		}

		byte[] bytes = bOut.toByteArray();

		ByteArrayInputStream bytesOut = new ByteArrayInputStream(bytes);
		//String strOut = new String(bytes);
		//OutputStream cOut = cPk.open(out, bytes.length);

		//cOut.write(bytes);

		//cOut.close();

		//out.close();
		
		System.out.println( "Encryption Process Completed" );
		
		return bytesOut;
	}
	
	
	public static byte[] encryptFile(
			byte[] inputData,
			//String outputFilePath,
			String compositePublicKeyPath,
			boolean armor
			) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(new FileInputStream(compositePublicKeyPath)), new JcaKeyFingerprintCalculator());        

		System.out.println( "Loaded Pub Key" );
		Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
		System.out.println( "Read Pub KeyRing" );

		// Add all recipient public keys to an array
		PGPPublicKey[] recipientPublicKeys = new PGPPublicKey[pgpPublicKeyRingCollection.size()];
		int i = 0;
		while (keyRingIterator.hasNext()) {
			PGPPublicKeyRing keyRing = keyRingIterator.next();
			recipientPublicKeys[i++] = keyRing.getPublicKey();
			System.out.println( "Iterate Pub Key" );
		}
		//FileOutputStream out = new FileOutputStream(outputFilePath);
		ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
		/*
		OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));
		if(armor)
		{
			out = new ArmoredOutputStream(out);        
		}
		*/
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
				PGPCompressedData.ZIP);
		/*
		PGPUtil.writeFileToLiteralData(
				comData.open(bOut),
				PGPLiteralData.BINARY,
				new File(inputFilePath));

		comData.close();
		*/
		
		OutputStream cos = comData.open(bOut); // open it with the final destination

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        // we want to generate compressed data. This might be a user option later,
        // in which case we would pass in bOut.
        OutputStream  pOut = lData.open(cos, // the compressed output stream
                                        PGPLiteralData.BINARY,
                                        PGPLiteralData.CONSOLE,  // "filename" to store
                                        inputData.length, // length of clear data
                                        new Date()  // current time
                                      );

        pOut.write(inputData);
        pOut.close();

        comData.close();
		

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(
						PGPEncryptedData.CAST5)
				.setWithIntegrityPacket(true)
				.setSecureRandom(
						new SecureRandom())
				.setProvider("BC"));

		for (PGPPublicKey publicKey : recipientPublicKeys) {
			cPk.addMethod(
					new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
					.setProvider("BC"));
		}

		byte[] bytes = bOut.toByteArray();

		OutputStream cOut = cPk.open(encryptedOut, bytes.length);

		cOut.write(bytes);

		cOut.close();		
		
		System.out.println( "Encryption Process Completed" );
		
		return encryptedOut.toByteArray();
	}
}
