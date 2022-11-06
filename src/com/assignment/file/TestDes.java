package com.assignment.file;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class TestDes {
    public String encrypt(String message, String key, boolean file) throws IOException {
        // construct a Des object
        Des des = new Des();
        // encrypt file
        if (file) {
            // address is where the encrypted file stores
            String encryptedFileName = des.encryptFile(message, key);
            System.out.println("Encrypted successfully! Please see the file in the " + encryptedFileName + ".");
            return "Encrypted successfully! Please see the file in: \n" + encryptedFileName + ".";
        }
        // encrypt plainText
        else {
            // convert the text into byte array
            byte[] strByte = message.getBytes(StandardCharsets.UTF_8);
            // convert the key into byte array
            byte[] keyByte = key.getBytes(StandardCharsets.UTF_8);
            // use the key to encrypt the text
            byte[] result = des.encrypt_data(strByte, keyByte);
            // convert byte into readable base64
            String base64Result = Base64.getEncoder().encodeToString(result);
            System.out.println("Encrypted: " + base64Result);
            return base64Result;
        }
    }

    // decrypt text
    public String decryptText(byte[] result, byte[] keyByte) {
        // decryption
        Des des = new Des();
        byte[] tem_result = des.decrypt_data(result, keyByte);
        System.out.println("Decrypted: " + new String(tem_result));
        return new String(tem_result);
    }

    // decrypt file
    public String decryptFile(String filePath, String key) throws IOException {
        // decryption
        Des des = new Des();
        // name of the decrypted file
        String decryptedFileName = des.decryptFile(filePath, key);
        return decryptedFileName;
    }
}
