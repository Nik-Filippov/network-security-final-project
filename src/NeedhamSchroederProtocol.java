import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.*;

public class NeedhamSchroederProtocol {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;
    private static final String MODE = "ECB"; // Choose "ECB", "CTR", or "CBC"

    // Store keys and initialisation vectors (IVs) for Alice and Bob
    private static final HashMap<String, byte[]> keys = new HashMap<>();
    private static final HashMap<String, IvParameterSpec> ivs = new HashMap<>();

    public static void main(String[] args) throws Exception {
        MessagePreprocessing messagePreprocessing = new MessagePreprocessing();
        // Step 0: Initialize TTP with Alice and Bob's keys and IVs
        initializeKeysAndIVs();

        String aliceID = stringToBinary("Alice");
        String bobID = stringToBinary("Bob");

        // Step 1: Alice → TTP: E(KA, "Alice∥Bob∥NA")
        String nonceAlice = stringToBinary(generateNonce("Alice"));
        List<String> requestToTTP = Arrays.asList(aliceID, bobID, nonceAlice);
        String encryptedRequestToTTP = encrypt(keys.get(aliceID), MessagePreprocessing.encodeMessages(requestToTTP), MODE, null);

        System.out.println("Step 1: Alice sends to TTP:");
        System.out.println("Encoded Plaintext (Alice∥Bob∥NA): " + requestToTTP);
        System.out.println("Encrypted: " + encryptedRequestToTTP);
        System.out.println();

        // Step 2: TTP → Alice: E(KA, "Bob∥NA∥KAB∥E(KB,KAB∥Alice)")
        String sessionKey = generateSessionKey();
        List<String> sessionKeyAndAliceID1 = Arrays.asList(sessionKey, aliceID);
        String encryptedForBob = stringToBinary(encrypt(keys.get(bobID), MessagePreprocessing.encodeMessages(sessionKeyAndAliceID1), MODE, null));
        List<String> responseToAlice = Arrays.asList(bobID, nonceAlice, stringToBinary(sessionKey), encryptedForBob);
        String encryptedResponseToAlice = encrypt(keys.get(aliceID), MessagePreprocessing.encodeMessages(responseToAlice), MODE, null);

        System.out.println("Step 2: TTP sends to Alice:");
        System.out.println("Encoded Plaintext (Bob∥NA∥KAB∥E(KB,KAB∥Alice)): " + responseToAlice);
        System.out.println("Encrypted: " + encryptedResponseToAlice);
        System.out.println();

        // Step 3: Alice → Bob: E(KB, "KAB∥Alice")
        List<String> sessionKeyAndAliceID2 = Arrays.asList(stringToBinary(sessionKey), aliceID);
        String encryptedToBob = encrypt(keys.get(bobID), MessagePreprocessing.encodeMessages(sessionKeyAndAliceID2), MODE, null);

        System.out.println("Step 3: Alice sends to Bob:");
        System.out.println("Encoded Plaintext (KAB∥Alice): " + sessionKeyAndAliceID2);
        System.out.println("Encrypted: " + encryptedToBob);
        System.out.println();

        // Step 4: Bob → Alice: E(KAB, "NB∥Bob")
        String nonceBob = generateNonce("Bob");
        List<String> responseToAliceFromBob = Arrays.asList(nonceBob, bobID);
        String encryptedResponseToAliceFromBob = encrypt(sessionKey.getBytes(), MessagePreprocessing.encodeMessages(responseToAliceFromBob), MODE, null);

        System.out.println("Step 4: Bob sends to Alice:");
        System.out.println("Encoded Plaintext (NB∥Bob): " + responseToAliceFromBob);
        System.out.println("Encrypted: " + encryptedResponseToAliceFromBob);
        System.out.println();

        // Step 5: Alice → Bob: E(KAB, "NB-1")
        String decrementNonce = Integer.toBinaryString(Integer.parseInt(nonceBob, 2) - 1);
        String finalResponse = encrypt(sessionKey.getBytes(), decrementNonce, MODE, null);

        System.out.println("Step 5: Alice sends to Bob:");
        System.out.println("Encrypted Plaintext (NB-1): " + decrementNonce);
        System.out.println("Encrypted: " + finalResponse);
        System.out.println();
        if(MODE.equals("ECB")) {
            System.out.println("Nonce received by Bob: " + Integer.parseInt(decrypt(sessionKey.getBytes(), finalResponse, MODE, null), 2));
            System.out.println();
        }

        // Encrypt a message twice in CTR/ECB mode to check if ciphertexts differ
        String message = "1234567890";
        String encryptedFirst = encrypt(keys.get(aliceID), message, "CTR", null);
        String encryptedSecond = encrypt(keys.get(aliceID), message, "CTR", null);

        System.out.println("Encrypted (CTR) First: " + encryptedFirst);
        System.out.println("Encrypted (CTR) Second: " + encryptedSecond);

        encryptedFirst = encrypt(keys.get(aliceID), message, "ECB", null);
        encryptedSecond = encrypt(keys.get(aliceID), message, "ECB", null);

        System.out.println("Encrypted (ECB) First: " + encryptedFirst);
        System.out.println("Encrypted (ECB) Second: " + encryptedSecond);

        encryptedFirst = encrypt(keys.get(aliceID), message, "CBC", null);
        encryptedSecond = encrypt(keys.get(aliceID), message, "CBC", null);

        System.out.println("Encrypted (CBC) First: " + encryptedFirst);
        System.out.println("Encrypted (CBC) Second: " + encryptedSecond);
    }

    // Initialize keys and IVs for Alice and Bob
    private static void initializeKeysAndIVs() throws Exception {
        keys.put(stringToBinary("Alice"), generateKey());
        keys.put(stringToBinary("Bob"), generateKey());
        ivs.put(stringToBinary("Alice"), generateIV());
        ivs.put(stringToBinary("Bob"), generateIV());
    }

    // Generate a random symmetric key
    private static byte[] generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        SecretKey key = keyGen.generateKey();
        return key.getEncoded();
    }

    // Generate a random IV
    private static IvParameterSpec generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Encrypt message with the provided key, mode, and IV
    private static String encrypt(byte[] key, String message, String mode, IvParameterSpec iv) throws Exception {
        // Choose padding based on mode
        String padding = (mode.equals("ECB") || mode.equals("CBC")) ? "PKCS5Padding" : "NoPadding"; // Use PKCS5 for ECB, NoPadding for CTR

        // Set up the Cipher with the appropriate padding
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + mode + "/" + padding);
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);

        if (mode.equals("CTR")) {
            // For CTR mode, use the IV as the counter
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);  // CTR mode requires IV (nonce)
        } else if (mode.equals("ECB")) {
            // For ECB mode, no IV is needed
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);  // ECB mode does not require IV
        } else {
            // For other modes like CBC, use IV
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        }

        // Encrypt the message and return as Base64 string
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decrypt(byte[] key, String encryptedMessage, String mode, IvParameterSpec iv) throws Exception {
        // Choose padding based on mode
        String padding = (mode.equals("ECB") || mode.equals("CBC")) ? "PKCS5Padding" : "NoPadding"; // Use PKCS5 for ECB, NoPadding for CTR

        // Set up the Cipher with the appropriate padding
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + mode + "/" + padding);
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);

        if (mode.equals("CTR")) {
            // For CTR mode, use the IV as the counter
            cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);  // CTR mode requires IV (nonce)
        } else if (mode.equals("ECB")) {
            // For ECB mode, no IV is needed
            cipher.init(Cipher.DECRYPT_MODE, keySpec);  // ECB mode does not require IV
        } else {
            // For other modes like CBC, use IV
            cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        }

        // Decrypt the message and return as string
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted);
    }

    // Generate a random nonce
    private static String generateNonce(String identity) {
        String nonce = Integer.toBinaryString(new SecureRandom().nextInt(100000));
        System.out.println("Generated Nonce for " + identity +  " : " + Integer.parseInt(nonce, 2));
        return nonce;
    }

    // Generate a session key
    private static String generateSessionKey() throws Exception {
        return Base64.getEncoder().encodeToString(generateKey()).substring(0, 16); // 16 bytes for AES-128
    }

    // Convert all stings to bits
    private static String stringToBinary(String message){
        String binary = "";
        for (char c : message.toCharArray()) {
            // Convert each character to its binary form and pad to 8 bits
            binary += String.format("%8s", Integer.toBinaryString(c))
                    .replace(' ', '0');
        }
        return binary;
    }
}






