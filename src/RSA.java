import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class RSA {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        List<String> argList= Arrays.asList(args);

        String usage = "Usage:\n" +
                       "  To generate a keypair of <bits> bits with a certanity <certanity> of keys\n" +
                       "  using prime numbers and save it in <public_key_file> and <secret_key_file>\n" +
                       "  files:\n" +
                       "    java RSA -K -p public_key_file -s secret_key_file -b bits -y certainty\n" +
                       "\n" +
                       "  To encrypt a file <plaintext_file> using <public_key_file> public key and save\n" +
                       "  the cipher text as <ciphertext_file> file:\n" +
                       "    java RSA -e -m plaintext_file -p public_key_file -c ciphertext_file\n" +
                       "\n" +
                       "  To decrypt a file <ciphertext_file> using <private_key_file> private key and\n" +
                       "  save the plaintext as <plaintext_file> file:\n" +
                       "    java RSA -d -c ciphertext_file -s secret_key_file -m plaintext_file\n" +
                       "\n" +
                       "  To see this help message:\n" +
                       "    java RSA -h\n";

        if (verifyArgs(argList, Arrays.asList("-K", "-p", "-s", "-b", "-y"))) {
            KeyPair k = new KeyPair(Integer.parseInt(getFlagArg(argList, "-b")),
                                    Double.parseDouble(getFlagArg(argList, "-y")));
            serialize(k.getPublicKey(), getFlagArg(argList, "-p"));
            serialize(k.getPrivateKey(), getFlagArg(argList, "-s"));
            System.exit(0);
        }

        if (verifyArgs(argList, Arrays.asList("-e", "-m", "-p", "-c"))) {
            // TODO: call encryption subroutine
            System.exit(0);
        }

        if (verifyArgs(argList, Arrays.asList("-d", "-c", "-s", "-p"))) {
            // TODO: call decryption subroutine
            System.exit(0);
        }

        if (verifyArgs(argList, Arrays.asList("-h"))) {
            System.out.print(usage);
            System.exit(0);
        }

        System.err.print("Error: incorrect arguments passed.\n\n");
        System.out.print(usage);
        System.exit(1);
    }

    // checks if all flags present and if all of them, except the first one, take an argument
    public static boolean verifyArgs(List<String> args, List<String> flags) {
        if (!args.containsAll(flags) || args.size() != 1 + (flags.size()-1)*2) {
            return false;
        }

        for (int i = 1; i < flags.size(); i ++) {
            String f = flags.get(i);
            int argIndex = args.indexOf(f) + 1;
            if (argIndex >= args.size() || args.get(argIndex).startsWith("-")) {
                return false;
            }
        }

        return true;
    }

    public static String getFlagArg(List<String> args, String flag) {
        return args.get(args.indexOf(flag)+1);
    }

    public static void serialize(Object obj, String filePath) throws IOException {
        try (
            FileOutputStream fileStream = new FileOutputStream(filePath);
            ObjectOutputStream objectStream = new ObjectOutputStream(fileStream);
        ) {
            objectStream.writeObject(obj);
        }
    }

    public static Object deserialize(String filePath) throws IOException, ClassNotFoundException {
        Object obj;
        try (
            FileInputStream fileStream = new FileInputStream(filePath);
            ObjectInputStream objectStream = new ObjectInputStream(fileStream);
        ) {
            obj = objectStream.readObject();
        }
        return obj;
    }

    public static BigInteger pad(PublicKey publicKey, BigInteger plaintext) {
        int k = (int) Math.ceil(publicKey.getModulus().bitLength()/8.0);
        int mLen = (int) Math.ceil(plaintext.bitLength()/8.0);

        if (mLen > k - 11) {
            throw new IllegalArgumentException("Error: Plaintext file is too long.");
        }

        byte[] result = new byte[k];

        result[0] = 0x00;
        result[1] = 0x02;

        Random rng = new SecureRandom();
        int psLen = k - mLen - 3;
        for (int i = 0; i < psLen; i ++) {
            byte[] b = new byte[1];
            do {
                rng.nextBytes(b);
            } while (b[0] == 0);
            result[2 + i] = b[0];
        }

        result[2 + psLen] = 0x00;

        System.arraycopy(plaintext.toByteArray(), 0, result, 2 + psLen + 1, mLen);

        return new BigInteger(result);
    }
}
