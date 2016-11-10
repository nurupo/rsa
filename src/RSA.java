public class RSA {
    public static void main(String[] args) {
        for (int i = 0; i < 100; i ++) {
            long startTime = System.currentTimeMillis();
            KeyPair k = new KeyPair(2048, 0.999);
            long endTime = System.currentTimeMillis();
            long totalTime = endTime - startTime;
            System.out.println("Generated keypair in " + totalTime / 1000.0 + " sec.");
        }
    }
}
