package io.github.legendff.mhw.save;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Savecrypt {
	private static final Key SECRET_KEY = new SecretKeySpec("xieZjoe#P2134-3zmaghgpqoe0z8$3azeq".getBytes(StandardCharsets.UTF_8), "Blowfish");
	
	public static byte[] changeEndianness(byte[] array) {
		byte[] newArray = new byte[array.length];

		for(int i = 0; i < array.length; i += 4) {
			newArray[i] = array[i+3];
			newArray[i+1] = array[i+2];
			newArray[i+2] = array[i+1];
			newArray[i+3] = array[i];
		}
		
		return newArray;
	}

	public static boolean isDecrypted(byte[] save) {
		return save[0] == 1 && save[1] == 0 && save[2] == 0 && save[3] == 0;
	}

	private static byte[] doCrypto(byte[] save, int opmode) {
		try {
			Cipher cipher = Cipher.getInstance("Blowfish/ecb/nopadding");
			cipher.init(opmode, SECRET_KEY);
			return changeEndianness(cipher.doFinal(changeEndianness(save)));
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static byte[] encrypt(byte[] save) {
		return doCrypto(save, Cipher.ENCRYPT_MODE);
	}
	
	public static byte[] decrypt(byte[] save) {
		return doCrypto(save, Cipher.DECRYPT_MODE);
	}
	
	public static boolean checkChecksum(byte[] save, byte[] checksum) {
		return Arrays.equals(Arrays.copyOfRange(save, 12, 32), checksum);
	}
	
	public static byte[] generateChecksum(byte[] save) {
		try {
			return changeEndianness(MessageDigest.getInstance("SHA-1").digest(Arrays.copyOfRange(save, 64, save.length)));
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static byte[] setChecksum(byte[] save, byte[] checksum) {
		System.arraycopy(checksum, 0, save, 12, 20);
		return save;
	}
	
	public static void main(String[] args) throws IOException {
		Path saveFile = Paths.get(args[0]);
		byte[] save = Files.readAllBytes(saveFile);
		boolean isDecrypted = isDecrypted(save);
		save = isDecrypted ? encrypt(setChecksum(save, generateChecksum(save))) : decrypt(save);
		Path outputFile = args.length > 1 ? Paths.get(args[1]) : Paths.get(saveFile.toString() + (isDecrypted ? ".enc" : ".dec"));
		Files.write(outputFile, save);
	}
}