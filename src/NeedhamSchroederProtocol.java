import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;

public class NeedhamSchroederProtocol {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;
    private static final String MODE = "CBC"; // Choose "ECB", "CTR", or "CBC"

    // Store keys and IVs for Alice and Bob
    private static final HashMap<String, byte[]> keys = new HashMap<>();
    private static final HashMap<String, IvParameterSpec> ivs = new HashMap<>();

    public static void main(String[] args) throws Exception {
        // Step 0: Initialize TTP with Alice and Bob's keys and IVs
        initializeKeysAndIVs();

        String alice = "Alice";
        String bob = "Bob";

        // Step 1: Alice → TTP: E(KA, "Alice∥Bob∥NA")
        String nonceAlice = generateNonce();
        String requestToTTP = alice + "∥" + bob + "∥" + nonceAlice;
        String encryptedRequestToTTP = encrypt(keys.get(alice), requestToTTP, MODE, null);

        System.out.println("Step 1: Alice sends to TTP:");
        System.out.println("Plaintext: " + requestToTTP);
        System.out.println("Encrypted: " + encryptedRequestToTTP);
        System.out.println();

        // Step 2: TTP → Alice: E(KA, "Bob∥NA∥KAB∥E(KB,KAB∥Alice)")
        String sessionKey = generateSessionKey();
        String encryptedForBob = encrypt(keys.get(bob), sessionKey + "∥" + alice, MODE, null);
        String responseToAlice = bob + "∥" + nonceAlice + "∥" + sessionKey + "∥" + encryptedForBob;
        String encryptedResponseToAlice = encrypt(keys.get(alice), responseToAlice, MODE, null);

        System.out.println("Step 2: TTP sends to Alice:");
        System.out.println("Plaintext: " + responseToAlice);
        System.out.println("Encrypted: " + encryptedResponseToAlice);
        System.out.println();

        // Step 3: Alice → Bob: E(KB, "KAB∥Alice")
        String encryptedToBob = encrypt(keys.get(bob), sessionKey + "∥" + alice, MODE, null);

        System.out.println("Step 3: Alice sends to Bob:");
        System.out.println("Plaintext: " + sessionKey + "∥" + alice);
        System.out.println("Encrypted: " + encryptedToBob);
        System.out.println();

        // Step 4: Bob → Alice: E(KAB, "NB∥Bob")
        String nonceBob = generateNonce();
        String responseToAliceFromBob = nonceBob + "∥" + bob;
        String encryptedResponseToAliceFromBob = encrypt(sessionKey.getBytes(), responseToAliceFromBob, MODE, null);

        System.out.println("Step 4: Bob sends to Alice:");
        System.out.println("Plaintext: " + responseToAliceFromBob);
        System.out.println("Encrypted: " + encryptedResponseToAliceFromBob);
        System.out.println();

        // Step 5: Alice → Bob: E(KAB, "NB-1")
        String decrementNonce = String.valueOf(Integer.parseInt(nonceBob) - 1);
        String finalResponse = encrypt(sessionKey.getBytes(), decrementNonce, MODE, null);

        System.out.println("Step 5: Alice sends to Bob:");
        System.out.println("Plaintext: " + decrementNonce);
        System.out.println("Encrypted: " + finalResponse);
        System.out.println();

        // Encrypt a message twice in CTR/ECB mode to check if ciphertexts differ
        String message = "1234567890";
        String encryptedFirst = encrypt(keys.get(alice), message, "CTR", null);
        String encryptedSecond = encrypt(keys.get(alice), message, "CTR", null);

        System.out.println("Encrypted (CTR) First: " + encryptedFirst);
        System.out.println("Encrypted (CTR) Second: " + encryptedSecond);

        encryptedFirst = encrypt(keys.get(alice), message, "ECB", null);
        encryptedSecond = encrypt(keys.get(alice), message, "ECB", null);

        System.out.println("Encrypted (ECB) First: " + encryptedFirst);
        System.out.println("Encrypted (ECB) Second: " + encryptedSecond);

        encryptedFirst = encrypt(keys.get(alice), message, "CBC", null);
        encryptedSecond = encrypt(keys.get(alice), message, "CBC", null);

        System.out.println("Encrypted (CBC) First: " + encryptedFirst);
        System.out.println("Encrypted (CBC) Second: " + encryptedSecond);
    }


    // Initialize keys and IVs for Alice and Bob
    private static void initializeKeysAndIVs() throws Exception {
        keys.put("Alice", generateKey());
        keys.put("Bob", generateKey());
        ivs.put("Alice", generateIV());
        ivs.put("Bob", generateIV());
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
    private static String generateNonce() {
        return String.valueOf(new SecureRandom().nextInt(100000));
    }

    // Generate a session key
    private static String generateSessionKey() throws Exception {
        return Base64.getEncoder().encodeToString(generateKey()).substring(0, 16); // 16 bytes for AES-128
    }
}






