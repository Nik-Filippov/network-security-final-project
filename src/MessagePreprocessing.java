import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class MessagePreprocessing {
    // Encode a list of bit sequences/messages into a single bit string
    public static String encodeMessages(List<String> messages) {
        int k = messages.size();
        // Use 5 bits to encode number of messages k
        StringBuilder encodedMessages = new StringBuilder();
        String encodedNumOfMessages = String.format(
                "%5s", Integer.toBinaryString(k)).replace(' ', '0');
        encodedMessages.append(encodedNumOfMessages);
        // Encode each message separately
        for (String m : messages) {
            int ni = m.length();
            // Use 8-bits to encode the length of message ni and add before message
            String encodedLengthOfMessage = String.format(
                    "%8s", Integer.toBinaryString(ni)).replace(' ', '0');
            encodedMessages.append(encodedLengthOfMessage).append(m);
        }
        return encodedMessages.toString();
    }

    // Decode an encoded bit string into list of messages
    public static List<String> decodeMessages(String encodedMessages) {
        List<String> decodedMessages = new ArrayList<>();
        // Decode the number of messages from the first 5 bits
        int k = Integer.parseInt(encodedMessages.substring(0, 5), 2);
        int index = 5;
        // Decode each message separately
        for (int i = 0; i < k; i++) {
            // Read message length from first 8 bits
            int ni = Integer.parseInt(encodedMessages.substring(index, index + 8), 2);
            index += 8;
            // Read the message
            String message = encodedMessages.substring(index, index + ni);
            index += ni;
            decodedMessages.add(message);
        }
        return decodedMessages;
    }

    // Run encoding & decoding (0 <= k <= 31 random messages with lengths between 1 and 5 bits each)
    public static void main(String[] args) {
        Random random = new Random();
        int k = random.nextInt(32);
        List<String> messages = new ArrayList<>();
        for (int i = 0; i < k; i++) {
            int ni = random.nextInt(5) + 1;
            StringBuilder message = new StringBuilder();
            for (int j = 0; j < ni; j++) {
                message.append(random.nextBoolean() ? "1" : "0");
            }
            messages.add(message.toString());
        }
        System.out.println("Messages to encode: " + messages);
        String encoded = encodeMessages(messages);
        System.out.println("Encoded Bit String: " + encoded);
        List<String> decoded = decodeMessages(encoded);
        System.out.println("Messages to decode: " + decoded);
        System.out.println(messages.equals(decoded) ? "Decoded messages match the original messages" :
                "Decoded messages does not match the original messages");
    }
}