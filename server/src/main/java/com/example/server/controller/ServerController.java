package com.example.server.controller;

import com.example.server.utility.DigitalSignatureUtil;
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
public class ServerController {
    private static KeyPair serverKeyPair;

    private static PublicKey clientPublicKeyObj;
    private static byte[] sharedSecret;

    @GetMapping("/public-key")
    public String getServerPublicKey() throws Exception {
        //Expose an endpoint to allow the client to request the server's public key

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        serverKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = serverKeyPair.getPublic();
        byte[] publicKeyBytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    @PostMapping("/client-key")
    public String receiveClientPublicKey(@RequestBody String clientPublicKey) throws Exception {

        // Accept the client's public key
        // Decode client's public key
        byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKey);

        // Derive a shared secret using ECDH
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
        clientPublicKeyObj = keyFactory.generatePublic(x509KeySpec);

        // Load the server's private key
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(serverPrivateKey);
        keyAgreement.doPhase(clientPublicKeyObj, true);

        // Generate the shared secret
        sharedSecret = keyAgreement.generateSecret();

        // Use the shared secret to derive an AES encryption key
        // For demonstration purposes, printing the shared secret
        System.out.println("Server Shared Secret (Base64): " + Base64.getEncoder().encodeToString(sharedSecret));

        PublicKey publicKey = serverKeyPair.getPublic();
        byte[] publicKeyBytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    @PostMapping("/encrypt")
    public static String encryptData(@RequestBody String dataToEncrypt) {
        try {
            System.out.println("dataToEncrypt"+dataToEncrypt);
            // Generate a unique salt for this encryption operation
            byte[] ivBytes = generateSalt();
            System.out.println("salt"+ivBytes.toString());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            // Create a secret key from the shared secret using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(Base64.getEncoder().encodeToString(sharedSecret).toCharArray(), ivBytes, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Sign the data with the server's private key
            String signature = DigitalSignatureUtil.sign(dataToEncrypt, serverKeyPair.getPrivate());

            System.out.println("signature : "+signature);
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

            System.out.println("Base64 :" +Base64.getEncoder().encodeToString(paddedData));

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

            System.out.println("saltLengthAndData : "+Base64.getEncoder().encodeToString(saltLengthAndData));
            System.out.println("===== : "+Base64.getEncoder().encodeToString(saltLengthAndData).substring(1 + saltLength, saltLengthAndData.length));

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
            if (!DigitalSignatureUtil.verify(data, receivedSignature, clientPublicKeyObj)) {
                return "Error: Signature verification failed.";
            }

            return encryptData(data);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error: Unable to decrypt data.";
        }
    }

    @GetMapping("/test")
    public String test() {
        try {
            String data = "Thiwank";
            String clientPublicKeyOb = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESR5i4BpAbGubN+a8pfjHKpZC6q7RD5th67yzco3QFQTQl37Oph4ABxYBbS/9+yPxLgX8oEQjol2jbf3UDxGLyw==";
            String receivedSignature = "MEUCIHwlC8OpQ+lo/Y+edkz19bdVE36gjaUAn1oc/u37dXk/AiEAix0I/YBBe87NPr0IdvSDDcVdMcH9vQKkNKNxHnXSFG4=";

            // Accept the client's public key
            // Decode client's public key
            byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKeyOb);

            // Derive a shared secret using ECDH
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
            PublicKey clientPublic = keyFactory.generatePublic(x509KeySpec);

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(clientPublic);
            byte[] temp = data.getBytes();
            sig.update(data.getBytes());
            byte[] signatureBytes = Base64.getDecoder().decode(receivedSignature);

            Boolean verified = sig.verify(signatureBytes);

            return verified ? "Verified" : "Error: Signature verification failed.";
        }
        catch (Exception e) {
            e.printStackTrace();
            return e.getMessage();
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