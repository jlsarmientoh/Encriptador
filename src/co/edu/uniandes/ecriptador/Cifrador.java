package co.edu.uniandes.ecriptador;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class Cifrador {
	
	private static String PRIVATE_KEY_PATH = "D:\\transfer\\smartHomePriKey.pri";
	private static String PUBLIC_KEY_PATH = "D:\\transfer\\smartHomePubKey.pub";
	private static final String KEY_ALGORITHM = "RSA";
	private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
	
	public Cifrador(String privateKeyPath, String publicKeyPath){
		PRIVATE_KEY_PATH = privateKeyPath;
		PUBLIC_KEY_PATH = publicKeyPath;
	}

	public static void main(String[] args) {
			/*KeyPairGenerator generator;
			try {
				generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
				generator.initialize(1024, new SecureRandom());
				KeyPair key = generator.generateKeyPair();
				PublicKey publicKey = key.getPublic();
				PrivateKey privateKey = key.getPrivate();
				System.out.println("=========Llave pública====================");
				System.out.println(publicKey.getFormat());
				System.out.println(publicKey.getEncoded());
				System.out.println(publicKey.toString());
				File archivoPublica = new File(PUBLIC_KEY_PATH);
				FileOutputStream outPublica = new FileOutputStream(archivoPublica);
				outPublica.write(Base64.encodeBase64(publicKey.getEncoded()));
				outPublica.close();
				
				System.out.println("=========Llaves privada====================");
				System.out.println(privateKey.getFormat());
				System.out.println(privateKey.getEncoded());
				System.out.println(privateKey.toString());
				File archivoPrivada = new File(PRIVATE_KEY_PATH);
				FileOutputStream outPrivada = new FileOutputStream(archivoPrivada);
				outPrivada.write(Base64.encodeBase64(privateKey.getEncoded()));
				outPrivada.close();
				
				System.out.println("=========Llaves generadas====================");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}*/
			
			Cifrador c = new Cifrador(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH);
			
			//Armado de la trama
			long timeStamp = System.currentTimeMillis();
			int idCasa = (int) (Math.floor(Math.random() * (100 - 1 + 1) + 1));
			//System.out.println("Time stamp(" + timeStamp + ") idCasa(" + idCasa
			//		+ ")");
			byte[] newData = new byte[20];

			newData[0] = (byte) timeStamp;
			newData[1] = (byte) (timeStamp >> 8);
			newData[2] = (byte) (timeStamp >> 16);
			newData[3] = (byte) (timeStamp >> 24);
			newData[4] = (byte) (timeStamp >> 32);
			newData[5] = (byte) (timeStamp >> 40);
			newData[6] = (byte) (timeStamp >> 48);
			newData[7] = (byte) (timeStamp >> 56);
			newData[8] = (byte) idCasa;
			newData[9] = (byte) (idCasa >> 8);

			for (int i = 0; i < (40 / 4); i += 2) {
				// 4 Sensores por byte: Donde el nibble bajo representa el bit
				// de cambio y el nibble alto el estado
				newData[i + 10] = (byte) 0x0C;
			}
			//Fin del armado de la trama
			
			
			
			
			/*System.out.println("Mensaje a encriptar: " + new String(Base64.encodeBase64(newData)));
			String mensajeEncriptado = new String(c.encrypt(newData));
			System.out.println("Mensaje encriptado: " + mensajeEncriptado);
			String mensajeDesencriptado = new String(c.decrypt(mensajeEncriptado.getBytes()));
			System.out.println("Mensaje desencriptado: " + new String(Base64.encodeBase64(mensajeDesencriptado.getBytes())));
			System.out.println("=================================================");*/
			
			/*System.out.println("Mensaje a encriptar: " + new String(newData));
			String mensajeEncriptado = new String(c.encrypt(newData));
			System.out.println("Mensaje encriptado: " + mensajeEncriptado);
			String mensajeDesencriptado = new String(c.decrypt(mensajeEncriptado.getBytes()));
			System.out.println("Mensaje desencriptado: " + mensajeDesencriptado);
			System.out.println("=================================================");*/
			/*
			try {
				System.out.print(readPublicKey());
				System.out.print(readPrivateKey());
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}*/
	}
	
	public byte[] encrypt(byte[] message){
		// Get a cipher object.
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, readPublicKey());
			 
			// Gets the raw bytes to encrypt, UTF8 is needed for
			// having a standard character set
			//byte[] stringBytes = message.getBytes("UTF8");
			byte[] stringBytes = message;
		 
			// encrypt using the cypher
			byte[] raw = cipher.doFinal(stringBytes);
			
			return Base64.encodeBase64(raw);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return "No se pudo encriptar".getBytes();
	}
	
	public byte[] decrypt(byte[] message){
		// Get a cipher object.
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, readPrivateKey());
			 
			byte[] raw = Base64.decodeBase64(message);
	 
			//decode the message
			byte[] stringBytes = cipher.doFinal(raw);
	 
			//converts the decoded message to a String
			//String clear = new String(stringBytes, "UTF8");
			//return clear.getBytes();
			return stringBytes;
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return "No se pudo desencriptar".getBytes();
			
	}
	
	private PublicKey readPublicKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
		  KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
	      FileInputStream pubKeyStream = new FileInputStream(PUBLIC_KEY_PATH);
	      int pubKeyLength = pubKeyStream.available();
	      byte[] pubKeyBytes = new byte[pubKeyLength];
	      pubKeyStream.read(pubKeyBytes);
	      pubKeyStream.close();
	      //System.out.println("Esta es la llave pública: " + pubKeyBytes);
	      X509EncodedKeySpec pubKeySpec 
	         = new X509EncodedKeySpec(Base64.decodeBase64(pubKeyBytes));
	      PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
	      /*System.out.println();
	      System.out.println("Public Key Info: ");
	      System.out.println("Algorithm = "+ pubKey.getAlgorithm());
	      System.out.println("Saved File = "+ PUBLIC_KEY_PATH);
	      System.out.println("Length = "+ pubKeyBytes.length);
	      System.out.println("format = "+ pubKey.getFormat());
	      System.out.println("toString = "+ pubKey.toString());
	      */
	      
	      return pubKey;
	}
	
	private PrivateKey readPrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
		  KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
	      /*System.out.println();
	      System.out.println("KeyFactory Object Info: ");
	      System.out.println("Algorithm = "+keyFactory.getAlgorithm());
	      System.out.println("Provider = "+keyFactory.getProvider());
	      System.out.println("toString = "+keyFactory.toString());*/

	      FileInputStream priKeyStream = new FileInputStream(PRIVATE_KEY_PATH);
	      int priKeyLength = priKeyStream.available();
	      byte[] priKeyBytes = new byte[priKeyLength];
	      priKeyStream.read(priKeyBytes);
	      priKeyStream.close();
	      //System.out.println("Esta es la llave privada: " + priKeyBytes);
	      PKCS8EncodedKeySpec priKeySpec 
	         = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKeyBytes));
	      /*System.out.println();
	      System.out.println("Private Key Specs Info: ");
	      System.out.println("Encoded = "+ priKeySpec.getEncoded());
	      System.out.println("Saved File = "+ PRIVATE_KEY_PATH);
	      System.out.println("Format = "+ priKeySpec.getFormat());
	      System.out.println("toString = "+ priKeySpec.toString());*/
	      
	      PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);
	      /*System.out.println();
	      System.out.println("Private Key Info: ");
	      System.out.println("Algorithm = "+ priKey.getAlgorithm());
	      System.out.println("Saved File = "+ PRIVATE_KEY_PATH);
	      System.out.println("Length = "+ priKeyBytes.length);
	      System.out.println("toString = "+ priKey.toString());*/
	      
	      return priKey;
	}

}
