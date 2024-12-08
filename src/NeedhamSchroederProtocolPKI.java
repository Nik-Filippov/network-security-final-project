import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;


public class NeedhamSchroederProtocolPKI {

    public static void main(String[] args){
        // Generate public and private keys for Alice, Bob, and TTP
        // Public key: int[1], int[0], private key: int[2], int[0]
        BigInteger[] aliceKeys = RSAKeyGeneration();
        BigInteger[] bobKeys = RSAKeyGeneration();
        BigInteger[] ttpKeys = RSAKeyGeneration();
        System.out.println("Public Keys:");
        System.out.println("Alice's public key: (" + aliceKeys[1] + ", " + aliceKeys[0] + ")");
        System.out.println("Bob's public key: (" + bobKeys[1] + ", " + bobKeys[0] + ")");
        System.out.println("TTP's public key: (" + ttpKeys[1] + ", " + ttpKeys[0] + ")");
        System.out.println();

        System.out.println("Private Keys:");
        System.out.println("Alice's private key: (" + aliceKeys[2] + ", " + aliceKeys[0] + ")");
        System.out.println("Bob's private key: (" + bobKeys[2] + ", " + bobKeys[0] + ")");
        System.out.println("TTP's private key: (" + ttpKeys[2] + ", " + ttpKeys[0] + ")");
        System.out.println();

        // Set IDs for Alice and Bob
        String aliceID = stringToBinary("Alice");
        System.out.println("Alice's binary representation of her ID, 'Alice': " + aliceID);
        String bobID = stringToBinary("Bob");
        System.out.println("Bob's binary representation of his ID, 'Bob' " + bobID);

        // Generate nonces for Alice and Bob
        int aliceNonceInt = (int) (Math.random() * 100000) + 1;
        String aliceNonce = Integer.toBinaryString(aliceNonceInt);
        System.out.println("Alice's nonce: " + aliceNonceInt);
        int bobNonceInt = (int) (Math.random() * 100000) + 1;
        String bobNonce = Integer.toBinaryString(bobNonceInt);
        System.out.println("Bob's nonce: " + bobNonceInt);
        System.out.println();

        // Concatonate Alice and Bob's IDs: IDA || IDB
        String encodedIdaIdb = concatonateString(aliceID, bobID);

        // Concatonate Bob's ID and Bob's public key: IDB || KeB
        String encodedIdbKeb = concatonateString(bobID, bobKeys[1].toString(2));
    
        // Concatonate Alice's nonce with Alices ID: NA || IDA
        String encodedNaIda = concatonateString(aliceNonce, aliceID);
       
        // Concatonate Bob's ID with Alice's ID: IDB || IDA
        String encodedIdbIda = concatonateString(bobID, aliceID);

        // Concatonate Alice's ID with Alice's public key: IDA || KeA
        String encodedIdaKea = concatonateString(aliceID, aliceKeys[1].toString(2));
        
        // Concatonate Alice's nonce with Bob's nonce: NA || NB
        String encodedNaNb = concatonateString(aliceNonce, bobNonce);
        

// **************** BEGIN PROTOCOL ******************


        // Step 1: Alice -> TTP: E(KeA, IDA, IDB)
        System.out.println("******** Step 1: Alice -> TTP: E(KeA, IDA, IDB) ********");
        BigInteger aliceToTTPMessage = new BigInteger(encodedIdaIdb, 2);
        // System.out.println("Alice to TTP Message: " + numAliceToTTPMessage);
        BigInteger aliceToTTPEncryption = RSAEncyption(aliceToTTPMessage, aliceKeys[1], aliceKeys[0]);
        System.out.println("Alice to TTP Encryption: " + aliceToTTPEncryption);
        System.out.println();

        // Step 2: TTP -> Alice: E(KdS, IDB || KeB)
        System.out.println("******** Step 2: TTP -> Alice: E(KdS, IDB || KeB) ********");
        BigInteger ttpToAliceMessage = new BigInteger(encodedIdbKeb, 2);
        System.out.println("TTP's Message to Alice: " + ttpToAliceMessage);
        BigInteger ttpToAliceEncryption = RSAEncyption(ttpToAliceMessage, ttpKeys[2], ttpKeys[0]);
        System.out.println("TTP to Alice Encryption: " + ttpToAliceEncryption);
        // Generate hash for TTP digital signature
        BigInteger ttpToAliceHash = generateHash(ttpToAliceMessage);
        System.out.println("TTP's hash of its message: " + ttpToAliceHash);
        BigInteger ttpToAliceSignature = RSAEncyption(ttpToAliceHash, ttpKeys[2], ttpKeys[0]);
        // Perform decryption on TTP's message and signature using TTP's public key
        BigInteger ttpToAliceDecryption = RSADecryption(ttpToAliceEncryption, ttpKeys[1], ttpKeys[0]);
        BigInteger ttpToAliceSigDecrypt = RSADecryption(ttpToAliceSignature, ttpKeys[1], ttpKeys[0]);
        System.out.println("Alice's decryption of TTP's message: " + ttpToAliceDecryption);
        System.out.println("Alice's decrypted hash of TTP's signature: " + ttpToAliceSigDecrypt);
        System.out.println("Does Alice's decrypted hash match TTP's signature: " + ((ttpToAliceHash.compareTo(ttpToAliceSigDecrypt) == 0) ? "TRUE" : "FALSE"));
        System.out.println("Does Alice's original message match TTP's decrypted message: " + ((ttpToAliceMessage.compareTo(ttpToAliceDecryption) == 0) ? "TRUE" : "FLASE"));
        // Generate session key
        String sessionKey = Integer.toBinaryString((int) (Math.random() * 100000) + 1);
        System.out.println("Session key, KAB: " + sessionKey);
        System.out.println();

        // Step 3: Alice -> Bob: E(KeB, NA, IDA)
        System.out.println("******** Step 3: Alice -> Bob: E(KeB, NA, IDA) ********");
        BigInteger aliceToBobMessage = new BigInteger(encodedNaIda, 2);
        System.out.println("Alice's Message to Bob: " + aliceToBobMessage);
        BigInteger aliceToBobEncryption = RSAEncyption(aliceToBobMessage, bobKeys[1], bobKeys[0]);
        System.out.println("Alice's Encryption to Bob: " + aliceToBobEncryption);
        // Generate hash, H(m), for Alice digital signature
        BigInteger aliceToBobHash = generateHash(aliceToBobMessage);
        System.out.println("Alice's hash of her message: " + aliceToBobHash);
        BigInteger aliceToBobSignature = RSAEncyption(aliceToBobHash, aliceKeys[2], aliceKeys[0]); // Using Alice's private key
        // Perform decryption of Alice's message and signature
        // BigInteger aliceToBobDecryption = RSADecryption(aliceToBobEncryption, bobKeys[2], bobKeys[0]); // Using Bob's private key
        BigInteger aliceToBobSigDecryp = RSADecryption(aliceToBobSignature, aliceKeys[1], aliceKeys[0]); // Using Alice's public key
        // System.out.println("Bob's Decryption of Alice's Message: " + aliceToBobDecryption);
        System.out.println("Bob's decrypted hash of Alice's signature: " + aliceToBobSigDecryp);
        // System.out.println("Does Alice's original message match Bob's decrypted message: " + ((aliceToBobMessage.compareTo(aliceToBobDecryption) == 0) ? "TRUE" : "FLASE"));
        System.out.println("Does Bob's decrypted hash match Alice's signature: " + ((aliceToBobHash.compareTo(aliceToBobSigDecryp) == 0) ? "TRUE" : "FALSE"));
        System.out.println();

        // ******** NEW PROTOCOL STEPS ********

        // Step 4 (Modification): Bob -> Alice: E(KeB, IDA || J)
        System.out.println("******** Step 4 (Modification): Bob -> Alice: E(KeB, IDA || J) ********");
        // Generate nonce, J
        String J = Integer.toBinaryString((int) (Math.random() * 100000) + 1);
        String encodedIdaJ = concatonateString(aliceID, J);
        BigInteger nonceJMessage = new BigInteger(encodedIdaJ, 2);
        System.out.println("Bob sends Alice his ID concatonated with his nonce J: " + nonceJMessage);
        BigInteger bobToAliceNonceJEncryption = RSAEncyption(nonceJMessage, bobKeys[1], bobKeys[0]);
        System.out.println();

        // Step 5  (Modification): Alice -> TTP: E(KdA, IDA || J)
        System.out.println("******** Step 5  (Modification): Alice -> TTP: E(KdA, IDA || J) ********");
        System.out.println("Alice sends TTP the message received from Bob, IDA || J: " + nonceJMessage);
        BigInteger aliceToTTPNonceJEncryption = RSAEncyption(nonceJMessage, aliceKeys[2], aliceKeys[0]);
        System.out.println();

        // Step 6 (Modification): TTP -> Alice: E(KdS, KAB || IDA || J)
        System.out.println("******** Step 6 (Modification): TTP -> Alice: E(KdS, KAB || IDA || J) ********");
        String sessionKeyNonceJ = concatonateString(sessionKey, encodedIdaJ);
        BigInteger ttpToAliceSessionKeyJ = new BigInteger(sessionKeyNonceJ, 2);
        System.out.println("TTP sends Alice the session key and nonce J: " + ttpToAliceSessionKeyJ);
        BigInteger ttpToAliceSessionKeyJEncryption = RSAEncyption(ttpToAliceSessionKeyJ, ttpKeys[2], ttpKeys[0]);
        System.out.println();

        // Step 7: Bob -> TTP: E(KeB, IDB || IDA)
        System.out.println("******** Step 7: Bob -> TTP: E(KeB, IDB || IDA) ********");
        BigInteger bobToTTPMessage = new BigInteger(encodedIdbIda, 2);
        BigInteger bobToTTPEncryption = RSAEncyption(bobToTTPMessage, bobKeys[1], bobKeys[0]);
        System.out.println("Bob to TTP Encryption: " + bobToTTPEncryption);
        System.out.println();

        // Step 8: TTP -> Bob: E(KdS, IDA || KeA)
        System.out.println("******** Step 8: TTP -> Bob: E(KdS, IDA || KeA) ********");
        BigInteger ttpToBobMessage = new BigInteger(encodedIdaKea, 2);
        System.out.println("TTP's message to Bob: " + ttpToBobMessage);
        BigInteger ttpToBobEncryption = RSAEncyption(ttpToBobMessage, ttpKeys[2], ttpKeys[0]);
        System.out.println("TTP to Bob Encryption: " + ttpToBobEncryption);
        // Generate hash for TTP digital signature
        BigInteger ttpToBobHash = generateHash(ttpToBobMessage);
        System.out.println("TTP's hash of its message: " + ttpToBobHash);
        BigInteger ttpToBobSignature = RSAEncyption(ttpToBobHash, ttpKeys[2], ttpKeys[0]);
        // Decrypt the hash and encrypted message
        BigInteger ttpToBobDecryption = RSADecryption(ttpToBobEncryption, ttpKeys[1], ttpKeys[0]);
        BigInteger ttpToBobSigDecrypt = RSADecryption(ttpToBobSignature, ttpKeys[1], ttpKeys[0]);
        System.out.println("Does Bob's decrypted hash match TTP's signature: " + ((ttpToBobHash.compareTo(ttpToBobSigDecrypt) == 0) ? "TRUE" : "FALSE"));
        System.out.println("Does Bob's original message match TTP's decrypted message: " + ((ttpToBobMessage.compareTo(ttpToBobDecryption) == 0) ? "TRUE" : "FLASE"));
        System.out.println();

        // Step 9: Bob -> Alice: E(KeA, NA || NB)
        System.out.println("******** Step 9: Bob -> Alice: E(KeA, NA || NB) ********");
        BigInteger bobToAliceMessage = new BigInteger(encodedNaNb, 2);
        BigInteger bobToAliceEncryption = RSAEncyption(bobToAliceMessage, aliceKeys[1], aliceKeys[0]);
        System.out.println("Bob's Encryption to Alice: " + bobToAliceEncryption);
        // Generate Bob's hash H(m)
        // BigInteger bobToAliceHash = generateHash(bobToAliceMessage);
        // BigInteger bobToAliceSignature = RSAEncyption(bobToAliceHash, bobKeys[2], bobKeys[0]); // Using Bob's private key
        // System.out.println("Bob's hash of his message: " + bobToAliceHash);
        // BigInteger bobToAliceDecryption = RSADecryption(bobToAliceEncryption, aliceKeys[2], aliceKeys[0]);
        // BigInteger bobToAliceSigDecrypt = RSADecryption(bobToAliceSignature, bobKeys[1], bobKeys[0]);
        // System.out.println("Alice's Decryption of Bob's Message: " + bobToAliceDecryption);
        // System.out.println("Alice's decrypted hash of Bob's signature: " + bobToAliceSigDecrypt);
        // System.out.println("Does Bob's original message match Alice's decrypted message: " + ((bobToAliceMessage.compareTo(bobToAliceDecryption) == 0) ? "TRUE" : "FALSE"));
        // System.out.println("Does Alice's decrypted hash match Bob's signature: " + ((bobToAliceHash.compareTo(bobToAliceSigDecrypt) == 0) ? "TRUE" : "FALSE"));
        System.out.println();

        // Step 10: Alice -> Bob: E(KeB, NB)
        System.out.println("******** Step 10: Alice -> Bob: E(KeB, KAB || J || NB) ********");
        String sessionKeyJ = concatonateString(sessionKey, J);
        String sessionKeyJNB = concatonateString(sessionKeyJ, bobNonce);
        BigInteger aliceToBobMessage2 = new BigInteger(sessionKeyJNB, 2);
        System.out.println("Alice's Message to Bob: " + aliceToBobMessage2);
        BigInteger aliceToBobEncryption2 = RSAEncyption(aliceToBobMessage2, bobKeys[1], bobKeys[0]);
        System.out.println("Alice's Encryption to Bob: " + aliceToBobEncryption2);
        // Generate hash, H(m), of Alice's message
        BigInteger aliceToBobHash2 = generateHash(aliceToBobMessage2);
        BigInteger aliceToBobSignature2 = RSADecryption(aliceToBobHash2, aliceKeys[2], aliceKeys[0]);
        System.out.println("Alice's hash of her message: " + aliceToBobHash2);
        BigInteger aliceToBobDecryption2 = RSADecryption(aliceToBobEncryption2, bobKeys[2], bobKeys[0]);
        BigInteger aliceToBobSigDecrypt2 = RSADecryption(aliceToBobSignature2, aliceKeys[1], aliceKeys[0]);
        System.out.println("Bob's Decryption of Alice's Message: " + aliceToBobDecryption2);
        System.out.println("Bob's decrypted hash of Alice's signature: " + aliceToBobSigDecrypt2);
        System.out.println("Does Bob retrieve its own nonce from Alice's encrypted message: " + ((aliceToBobMessage2.compareTo(aliceToBobDecryption2) == 0) ? "TRUE" : "FALSE"));
        System.out.println("Does Bob's decrypted hash match Alice's signature: " + ((aliceToBobHash2.compareTo(aliceToBobSigDecrypt2) == 0) ? "TRUE" : "FALSE"));
        System.out.println();
    }

    private static BigInteger gcd(BigInteger a, BigInteger b){ // compute the gcd of two numbers
        if (b.compareTo(a) > 0){
            BigInteger temp = b;
            b = a;
            a = temp;
        }
        while (!(a.mod(b)).equals(new BigInteger("0"))){
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return b;
    }
    private static BigInteger moduloInverse(BigInteger a, BigInteger n){
        // verify gcd of a and n equals 1
        BigInteger gcd = gcd(a, n);
        if (!gcd.equals(new BigInteger("1"))){
            return new BigInteger("-1"); // a and n are not relatively prime
        }
        BigInteger temp = new BigInteger("1");
        while (!((temp.add(n)).mod(a)).equals(new BigInteger("0"))){
            temp = temp.add(n);
        }
        temp = temp.add(n);
        return temp.divide(a);
    }

    private static BigInteger[] RSAKeyGeneration(){
        SecureRandom rand = new SecureRandom();        
        BigInteger p = new BigInteger("-1");
        BigInteger q = new BigInteger("-1");
        // generate large q and p and check if they are prime
        do {
            // Generate two random BigIntegers of up to 50 bits
            p = new BigInteger(50, rand);
            q = new BigInteger(50, rand);
            if (!p.isProbablePrime(100)) {
                p = BigInteger.valueOf(-1); // Assign -1 if p is not prime
            }
            // Check if q is prime
            if (!q.isProbablePrime(100)) {
                q = BigInteger.valueOf(-1); // Assign -1 if q is not prime
            }
        } while (p.equals(new BigInteger("-1")) || q.equals(new BigInteger("-1")));
        BigInteger n = p.multiply(q);
        BigInteger euler = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = new BigInteger(String.valueOf((int) (Math.random() * 1000) + 1));
        while (!gcd(e, euler).equals(BigInteger.ONE)){
            e = new BigInteger(String.valueOf((int) (Math.random() * 1000) + 1));
        }
        BigInteger d = moduloInverse(e, euler);
        BigInteger[] keys = new BigInteger[]{n, e, d};
        return keys;
    }

    private static BigInteger stringToAscii(String message){
        String asciiMessage = "";
        for (char c : message.toCharArray()){
            String asciiCharacter = String.valueOf((int) c);
            asciiMessage += asciiCharacter;
        }
        BigInteger numAsciiMessage = new BigInteger(asciiMessage);
        return numAsciiMessage;
    }

    private static BigInteger RSAEncyption(BigInteger m, BigInteger e, BigInteger n){ 
        return m.modPow(e, n);
    }

    private static BigInteger RSADecryption(BigInteger c, BigInteger d, BigInteger n){
        return c.modPow(d, n);
    }

    private static BigInteger generateHash(BigInteger message){
        String stringMessage = message.toString(10);
        int hashCode = stringMessage.hashCode();
        // Convert the signed hashCode to an unsigned positive value
        return new BigInteger(Integer.toUnsignedString(hashCode));
    }
    
    private static String stringToBinary(String message){
        String binary = "";
        for (char c : message.toCharArray()) {
            // Convert each character to its binary form and pad to 8 bits
            binary += String.format("%8s", Integer.toBinaryString(c))
                         .replace(' ', '0');
        }
        return binary;
    }
    
    private static String concatonateString(String message1, String message2){
        List<String> list = new ArrayList<>();
        list.add(message1); list.add(message2);
        MessagePreprocessing messagePreprocessing = new MessagePreprocessing();
        return messagePreprocessing.encodeMessages(list);
    }

}
