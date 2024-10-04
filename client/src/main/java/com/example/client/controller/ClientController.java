package com.example.client.controller;

import com.example.client.utility.DigitalSignatureUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@RestController
public class ClientController {
    private KeyPair clientKeyPair;
    private byte[] sharedSecret;

    private PublicKey serverPublicKeyObj;

    @GetMapping("/public-key")
    public String getClientPublicKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        clientKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = clientKeyPair.getPublic();
        byte[] publicKeyBytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    @PostMapping("/server-key")
    public void receiveServerPublicKey(@RequestBody String serverPublicKey) throws Exception {

        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
        serverPublicKeyObj = keyFactory.generatePublic(x509KeySpec);

        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(clientPrivateKey);
        keyAgreement.doPhase(serverPublicKeyObj, true);

        sharedSecret = keyAgreement.generateSecret();
        System.out.println("Client's Shared Secret (Base64): " + Base64.getEncoder().encodeToString(sharedSecret));
    }

    @PostMapping("/encrypt")
    public String encryptData(@RequestBody String dataToEncrypt) {
        try {
            // Generate a unique salt for this encryption operation
            byte[] ivBytes = generateSalt();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            // Create a secret key from the shared secret using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(Base64.getEncoder().encodeToString(sharedSecret).toCharArray(), ivBytes, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Sign the data with the server's private key
            String signature = DigitalSignatureUtil.sign(dataToEncrypt, clientKeyPair.getPrivate());

            // Combine the data and signature
            String dataToEncryptWithSignature = dataToEncrypt + ":" + signature;

            // Pad the input data to a multiple of 16 bytes using PKCS7 padding
            int blockSize = 16;
            byte[] dataBytes = dataToEncryptWithSignature.getBytes("UTF-8");
            int paddingLength = blockSize - (dataBytes.length % blockSize);
            byte[] paddedData = new byte[dataBytes.length + paddingLength];
            System.arraycopy(dataBytes, 0, paddedData, 0, dataBytes.length);
            for (int i = dataBytes.length; i < paddedData.length; i++) {
                paddedData[i] = (byte) paddingLength;
            }

            // Initialize the cipher for encryption with the IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

            // Encrypt the data
            byte[] encryptedData = cipher.doFinal(paddedData);

            // Combine the salt length, salt, and encrypted data into a single byte array
            byte[] saltLengthAndData = new byte[ivBytes.length + encryptedData.length + 1];
            saltLengthAndData[0] = (byte) ivBytes.length;
            System.arraycopy(ivBytes, 0, saltLengthAndData, 1, ivBytes.length);
            System.arraycopy(encryptedData, 0, saltLengthAndData, ivBytes.length + 1, encryptedData.length);

            return Base64.getEncoder().encodeToString(saltLengthAndData);

        } catch (Exception e) {
            e.printStackTrace();
            return "Error: Unable to encrypt data.";
        }
    }

    @PostMapping("/decrypt")
    public String decryptData(@RequestBody String encryptedDataWithIV) {
        try {
            byte[] saltLengthAndData = Base64.getDecoder().decode(encryptedDataWithIV);

            // Ensure that the minimum expected length is met
            if (saltLengthAndData.length < 17) {
                return "Error: Invalid encrypted data.";
            }

            // Extract the salt length
            int saltLength = saltLengthAndData[0];
            if (saltLength <= 0 || saltLength > 16) {
                return "Error: Invalid salt length.";
            }

            // Extract the salt
            byte[] ivBytes = new byte[saltLength];
            System.arraycopy(saltLengthAndData, 1, ivBytes, 0, saltLength);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            // Create a secret key from the shared secret using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(Base64.getEncoder().encodeToString(sharedSecret).toCharArray(), ivBytes, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Initialize the cipher for decryption with the IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            // Decrypt the data
            byte[] decryptedData = cipher.doFinal(saltLengthAndData, 1 + saltLength, saltLengthAndData.length - 1 - saltLength);

            // Remove PKCS7 padding
            int paddingLength = decryptedData[decryptedData.length - 1];
            byte[] originalData = new byte[decryptedData.length - paddingLength];
            System.arraycopy(decryptedData, 0, originalData, 0, originalData.length);

            // Split the data into the actual data and the signature
            String[] dataAndSignature = new String(originalData, "UTF-8").split(":", 2);
            if (dataAndSignature.length != 2) {
                return "Error: Invalid data format.";
            }

            String data = dataAndSignature[0];
            String receivedSignature = dataAndSignature[1];

            // Verify the digital signature
            if (!DigitalSignatureUtil.verify(data, receivedSignature, serverPublicKeyObj)) {
                return "Error: Signature verification failed.";
            }

            return data;
        } catch (Exception e) {
            e.printStackTrace();
            return "Error: Unable to decrypt data.";
        }
    }

    private static byte[] generateSalt() {
        try {
            // Generate a secure random salt
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            byte[] saltBytes = new byte[16]; // Adjust the length as needed
            secureRandom.nextBytes(saltBytes);
            return saltBytes;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return new byte[16]; // Fallback value
        }
    }
}
