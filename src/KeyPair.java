import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class KeyPair {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public KeyPair(int bits, double millerRabinCertainty) {
        BigInteger prime1 = randomProbablyPrime(bits/2, millerRabinCertainty);
        BigInteger prime2 = randomProbablyPrime(bits/2 + bits%2, millerRabinCertainty);
        BigInteger modulus = prime1.multiply(prime2);
        BigInteger prime1MinusOne = prime1.subtract(BigInteger.ONE);
        BigInteger prime2MinusOne = prime2.subtract(BigInteger.ONE);
        BigInteger totientModulus = prime1MinusOne.multiply(prime2MinusOne);
        BigInteger publicExponent;
        do {
            publicExponent = uniformRandomInExclusiveRange(BigInteger.ONE, totientModulus);
        } while (!publicExponent.gcd(totientModulus).equals(BigInteger.ONE));

        BigInteger privateExponent = publicExponent.modInverse(totientModulus);
        if (privateExponent.compareTo(BigInteger.ZERO) < 0 || privateExponent.compareTo(modulus) > 0) {
            throw new ArithmeticException("Calculated public exponent is out of the range of [0. n].");
        }

        BigInteger exponent1 = privateExponent.mod(prime1MinusOne);
        BigInteger exponent2 = privateExponent.mod(prime2MinusOne);
        BigInteger coefficient = prime2.modInverse(prime1);

        privateKey = new PrivateKey(modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient);
        publicKey = new PublicKey(modulus,publicExponent);
    }

    private static BigInteger randomProbablyPrime(int bits, double certainty) {
        // 1 - 2^(-x) = certainty => x = -1 * ln(1 - certainty) / ln(2)
        // since x has to be integer, we take the smallest integer x satisfying: 1 - 2^(-x) => certainty
        // by taking the ceiling.
        int tests = (int) Math.ceil(-Math.log(1 - certainty) / Math.log(2));
        return new BigInteger(bits, tests, new SecureRandom());
    }

    // returns n such that min < n < max
    private static BigInteger uniformRandomInExclusiveRange(BigInteger min, BigInteger max) {
        BigInteger n;
        Random rng = new SecureRandom();
        int bits = max.bitLength();
        //System.out.println("Generating a random " + bits + "bit integer between " + min + " and " + max);
        do {
            n = new BigInteger(bits, rng);
            // we drop random numbers out of range of (min, max) because clamping or mod'ing would skew the distribution
            // of random numbers. we want to keep the uniform distribution.
        } while (n.compareTo(min) <= 0 || n.compareTo(max) >= 0);

        return n;
    }

}
