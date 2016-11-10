import java.io.*;

public class RSA {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        KeyPair k = new KeyPair(256, 0.999);

        PrivateKey privateKey1 = k.getPrivateKey();
        System.out.println(privateKey1.getPrime1());
        System.out.println(privateKey1.getPrime2());
        serialize(privateKey1, "./private_key.dat");

        PrivateKey privateKey2 = (PrivateKey) deserialize("./private_key.dat");
        System.out.println(privateKey2.getPrime1());
        System.out.println(privateKey2.getPrime2());
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
}
