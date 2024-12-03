import java.math.BigInteger;
import java.security.SecureRandom;

public class NeedhamSchroederProtocolPKI {
    public static void main(String[] args) throws Exception{
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
        BigInteger aliceID = stringToAscii("Alice");
        BigInteger bobID = stringToAscii("Bob");

        // Generate nonces for Alice and Bob
        int aliceNonce = (int) (Math.random() * 100000) + 1;
        int bobNonce = (int) (Math.random() * 100000) + 1;
        
        // Step 1: Alice -> TTP: E(KeA, IDA, IDB)
        System.out.println("******** Step 1: Alice -> TTP: E(KeA, IDA, IDB) ********");
        BigInteger aliceToTTPMessage = new BigInteger(aliceID + "" + bobID);
        // System.out.println("Alice to TTP Message: " + numAliceToTTPMessage);
        BigInteger aliceToTTPEncryption = RSAEncyption(aliceToTTPMessage, aliceKeys[1], aliceKeys[0]);
        System.out.println("Alice to TTP Encryption: " + aliceToTTPEncryption);
        System.out.println();

        // Step 2: TTP -> Alice: E(KdS, IDB || KeB)
        System.out.println("******** Step 2: TTP -> Alice: E(KdS, IDB || KeB) ********");
        BigInteger ttpToAliceMessage = new BigInteger(bobID + "" + bobKeys[1] + "" + bobKeys[0]);
        BigInteger ttpToAliceEncryption = RSAEncyption(ttpToAliceMessage, ttpKeys[2], ttpKeys[0]);
        System.out.println("TTP to Alice Encryption: " + ttpToAliceEncryption);
        System.out.println();

        // Step 3: Alice -> Bob: E(KeB, NA, IDA)
        System.out.println("******** Step 3: Alice -> Bob: E(KeB, NA, IDA) ********");
        BigInteger aliceToBobMessage = new BigInteger(aliceNonce + "" + aliceID);
        System.out.println("Alice's Message to Bob: " + aliceToBobMessage);
        BigInteger aliceToBobEncryption = RSAEncyption(aliceToBobMessage, bobKeys[1], bobKeys[0]);
        System.out.println("Alice's Encryption to Bob: " + aliceToBobEncryption);
        BigInteger aliceToBobDecryption = RSADecryption(aliceToBobEncryption, bobKeys[2], bobKeys[0]);
        System.out.println("Bob's Decryption of Alice's Message: " + aliceToBobDecryption);
        System.out.println("Does Alice's original message match Bob's decrypted message: " + ((aliceToBobMessage.compareTo(aliceToBobDecryption) == 0) ? "TRUE" : "FLASE"));
        System.out.println();

        // Step 4: Bob -> TTP: E(KeB, IDB || IDA)
        System.out.println("******** Step 4: Bob -> TTP: E(KeB, IDB || IDA) ********");
        BigInteger bobToTTPMessage = new BigInteger(bobID + "" + aliceID);
        BigInteger bobToTTPEncryption = RSAEncyption(bobToTTPMessage, bobKeys[1], bobKeys[0]);
        System.out.println("Bob to TTP Encryption: " + bobToTTPEncryption);
        System.out.println();

        // Step 5: TTP -> Bob: E(KdS, IDA || KeA)
        System.out.println("******** Step 5: TTP -> Bob: E(KdS, IDA || KeA) ********");
        BigInteger ttpToBobMessage = new BigInteger(aliceID + "" + aliceKeys[1] + "" + aliceKeys[0]);
        BigInteger ttpToBobMessageEncryption = RSAEncyption(ttpToBobMessage, ttpKeys[2], ttpKeys[0]);
        System.out.println("TTP to Bob Encryption: " + ttpToBobMessageEncryption);
        System.out.println();

        // Step 6: Bob -> Alice: E(KeA, NA || NB)
        System.out.println("******** Step 6: Bob -> Alice: E(KeA, NA || NB) ********");
        BigInteger bobToAliceMessage = new BigInteger(aliceNonce + "" + bobNonce);
        System.out.println("Bob's Message to Alice: " + bobToAliceMessage);
        BigInteger bobToAliceEncryption = RSAEncyption(bobToAliceMessage, aliceKeys[1], aliceKeys[0]);
        System.out.println("Bob's Encryption to Alice: " + bobToAliceEncryption);
        BigInteger bobToAliceDecryption = RSADecryption(bobToAliceEncryption, aliceKeys[2], aliceKeys[0]);
        System.out.println("Alice's Decryption of Bob's Message: " + bobToAliceDecryption);
        System.out.println("Does Bob's original message match Alice's decrypted message: " + ((bobToAliceMessage.compareTo(bobToAliceDecryption) == 0) ? "TRUE" : "FALSE"));
        System.out.println();

        // Step 7: Alice -> Bob: E(KeB, NB)
        System.out.println("******** Step 7: Alice -> Bob: E(KeB, NB) ********");
        BigInteger aliceToBobMessage2 = new BigInteger(String.valueOf(bobNonce));
        System.out.println("Alice's Message to Bob: " + aliceToBobMessage2);
        BigInteger aliceToBobEncryption2 = RSAEncyption(aliceToBobMessage2, bobKeys[1], bobKeys[0]);
        System.out.println("Alice's Encryption to Bob: " + aliceToBobEncryption2);
        BigInteger aliceToBobDecryption2 = RSADecryption(aliceToBobEncryption2, bobKeys[2], bobKeys[0]);
        System.out.println("Bob's Decryption of Alice's Message: " + aliceToBobDecryption2);
        System.out.println("Does Alice's original message match Bob's decrypted message: " + ((aliceToBobMessage2.compareTo(aliceToBobDecryption2) == 0) ? "TRUE" : "FALSE"));
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
            // Generate two random BigIntegers of up to 512 bits
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

    // private static String stringToAsciiPadded(String message){
    //     String asciiMessage = "";
    //     for (char c : message.toCharArray()){
    //         String asciiCharacter = String.valueOf((int) c);
    //         while (asciiCharacter.length() < 8){
    //             asciiCharacter = "0" + asciiCharacter;
    //         }
    //         asciiMessage += asciiCharacter;
    //         System.out.println(asciiMessage);
    //     }
    //     return asciiMessage;
    // }

    private static BigInteger stringToAscii(String message){
        String asciiMessage = "";
        for (char c : message.toCharArray()){
            String asciiCharacter = String.valueOf((int) c);
            asciiMessage += asciiCharacter;
        }
        BigInteger numAsciiMessage = new BigInteger(asciiMessage);
        return numAsciiMessage;
    }

    // private static String asciiToString(String ascii){
    //     String decryptedMessage = "";
    //     int messageLength = ascii.length() / 8;
    //     for (int i = 0; i < messageLength; i++){
    //         // Extract the 8-bit ASCII values (in string form)
    //         String asciiString = ascii.substring(8 * i, 8 * (i + 1));
    //         // System.out.println(asciiString);
    //         int asciiValue = Integer.parseInt(asciiString); // Convert to integer
    //         decryptedMessage += (char) asciiValue; // Convert to char and concatenate
    //     }
    //     return decryptedMessage;
    // }

    private static BigInteger RSAEncyption(BigInteger m, BigInteger e, BigInteger n){ // m < n
        return m.modPow(e, n);
    }

    private static BigInteger RSADecryption(BigInteger c, BigInteger d, BigInteger n){
        return c.modPow(d, n);
    }
    
}
