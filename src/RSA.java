import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class RSA {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        List<String> argList = Arrays.asList(args);

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
            System.out.println(k.getPublicKey());
            System.out.println(k.getPrivateKey());
            serialize(k.getPublicKey(), getFlagArg(argList, "-p"));
            serialize(k.getPrivateKey(), getFlagArg(argList, "-s"));
            System.exit(0);
        }

        if (verifyArgs(argList, Arrays.asList("-e", "-m", "-p", "-c"))) {
            PublicKey publicKey = (PublicKey)deserialize(getFlagArg(argList, "-p"));
            byte[] plaintext = readByteFile(getFlagArg(argList, "-m"), bitsToBytes(publicKey.getModulus().bitLength()));
            System.out.println("plaintext=" + byteArrayToHex(plaintext));
            byte[] ciphertext = encrypt(publicKey, plaintext);
            System.out.println("ciphertext=" + byteArrayToHex(ciphertext));
            writeByteFile(getFlagArg(argList, "-c"), ciphertext);
            System.exit(0);
        }

        if (verifyArgs(argList, Arrays.asList("-d", "-c", "-s", "-m"))) {
            PrivateKey privateKey = (PrivateKey)deserialize(getFlagArg(argList, "-s"));
            byte[] ciphertext = readByteFile(getFlagArg(argList, "-c"), bitsToBytes(privateKey.getModulus().bitLength()));
            System.out.println("ciphertext=" + byteArrayToHex(ciphertext));
            byte[] plaintext = decrypt(privateKey, ciphertext);
            System.out.println("plaintext=" + byteArrayToHex(plaintext));
            writeByteFile(getFlagArg(argList, "-m"), plaintext);
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

    public static int bitsToBytes(int bits) {
        return (int)Math.ceil(bits/8.0);
    }

    public static byte[] readByteFile(String filePath, int maxBytes) throws IOException {
        File file = new File(filePath);

        if (file.length() > maxBytes) {
            throw new IllegalArgumentException("Error: file " + filePath + " is larger than " + maxBytes + " + bytes.");
        }

        byte[] bytes = new byte[(int)file.length()];

        int offset = 0;

        try (FileInputStream fileStream = new FileInputStream(file);) {
            while (true) {
                int ret = fileStream.read(bytes, offset, bytes.length - offset);
                if (ret <= 0) {
                    break;
                }
                offset += ret;
            }
        }

        return bytes;
    }

    public static void writeByteFile(String filePath, byte[] data) throws IOException {
        try (FileOutputStream fileStream = new FileOutputStream(filePath);) {
            fileStream.write(data);
        }
    }

    public static String byteArrayToHex(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public static byte[] pad(PublicKey publicKey, byte[] plaintext) {
        int k = bitsToBytes(publicKey.getModulus().bitLength());
        int mLen = plaintext.length;

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

        System.arraycopy(plaintext, 0, result, 2 + psLen + 1, mLen);

        return result;
    }

    public static byte[] unpad(PrivateKey privateKey, byte[] paddedPlaintext) {
        if (paddedPlaintext[0] != 0x02) {
            throw new IllegalArgumentException("Error: incorrect pad sequence, the ciphertext was likely tempered with.");
        }

        int i = 1;
        while (paddedPlaintext[i] != 0x00) {
            i ++;
        }

        if (i < 9) {
            throw new IllegalArgumentException("Error: incorrect pad sequence, the ciphertext was likely tempered with.");
        }

        byte[] result = new byte[paddedPlaintext.length - (i+1)];

        System.arraycopy(paddedPlaintext, i+1, result, 0, result.length);

        return result;
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] plaintext) {
        BigInteger paddedPlaintext = new BigInteger(pad(publicKey, plaintext));

        System.out.println("padded plaintext=" + paddedPlaintext.toString(16));

        // https://tools.ietf.org/html/rfc3447#section-5.1.1
        if (paddedPlaintext.compareTo(publicKey.getModulus()) >= 0) {
            throw new IllegalArgumentException("Error: plaintext integer representation is greater than modulus - 1");
        }

        return paddedPlaintext.modPow(publicKey.getPublicExponent(), publicKey.getModulus()).toByteArray();
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) {
        BigInteger ciphertextInt = new BigInteger(ciphertext);

        BigInteger m1 = ciphertextInt.modPow(privateKey.getExponent1(), privateKey.getPrime1());
        BigInteger m2 = ciphertextInt.modPow(privateKey.getExponent2(), privateKey.getPrime2());
        BigInteger h = m1.subtract(m2).multiply(privateKey.getCoefficient()).mod(privateKey.getPrime1());

        System.out.println("m1=" + m1.toString(16));
        System.out.println("m2=" + m2.toString(16));
        System.out.println("h=" + h.toString(16));

        BigInteger paddedPlaintext = privateKey.getPrime2().multiply(h).add(m2);

        System.out.println("padded plaintext (m)=" + paddedPlaintext.toString(16));

        return unpad(privateKey, paddedPlaintext.toByteArray());
    }
}
