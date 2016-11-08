import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;

public class KeyPair {

    private PrivateKey sk;
    private PublicKey pk;

    public PrivateKey getSk() {
        return sk;
    }

    public PublicKey getPk() {
        return pk;
    }

    public KeyPair(int bits, double millerRabinCertainty) {
        BigInteger prime1 = randomPrime(bits, millerRabinCertainty);
        BigInteger prime2 = randomPrime(bits, millerRabinCertainty);
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

        sk = new PrivateKey(modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient);
        pk = new PublicKey(modulus,publicExponent);

    }

    private static BigInteger TWO = new BigInteger("2");

    private static BigInteger randomPrime(int bits, double millerRabinCertainty) {
        Random rng = new SecureRandom();
        ArrayList<BigInteger> firstPrimes = firstPrimes(2000);

        BigInteger n;
generate_n:
        while (true) {
            n = new BigInteger(bits, rng);
            n = n.setBit(0);
            n = n.setBit(bits - 1);
            while (true) {
                boolean probablyPrime = true;
                // should not be divisible by first 2000 primes
                for (BigInteger p : firstPrimes) {
                    if (n.mod(p).equals(BigInteger.ZERO)) {
                        probablyPrime = false;
                        break;
                    }
                }
                // should pass Miller Rabin
                if (probablyPrime && !isProbablyPrime(n, millerRabinCertainty)) {
                    probablyPrime = false;
                }
                if (probablyPrime) {
                    break generate_n;
                }
                n = n.add(TWO);
                // if `n` has expanded beyond `bits` bits because of our repeated addition -- start over
                if (n.bitLength() != bits) {
                    continue generate_n;
                }
            }
        }

        return n;
    }

    // sieve of Eratosthenes
    // 1 is not considered to be a prime, i.e. it's excluded from the return value
    private static ArrayList<BigInteger> firstPrimes(int n) {
        boolean[] sieve = new boolean[n+1];

        ArrayList<BigInteger> primes = new ArrayList<>();

        for (int i = 2; i <= n; i ++) {
            if (!sieve[i]) {
                primes.add(BigInteger.valueOf(i));
                for (int j = i*i; j <= n; j += i) {
                    sieve[j] = true;
                }
            }
        }

        return primes;
    }

    // Miller Rabin
    private static boolean isProbablyPrime(BigInteger n, double certainty) {
        if (n.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("n should be a positive non-zero number");
        }
        if (n.compareTo(TWO) <= 0) {
            return true;
        }
        if (certainty < 0 || certainty > 1) {
            throw new IllegalArgumentException("certainty should be between 0 and 1");
        }

        int tests = 1;
        // find t in: 1 - 4^-t < certainty
        while (1. - 1./Math.pow(4, tests) < certainty) {
            tests ++;
        }
        //System.out.println("Running " + tests + " tests");
        int k = 0;
        BigInteger nMinusOne = n.subtract(BigInteger.ONE);
        BigInteger q = nMinusOne;
        // find q and k in: n-1 = q * 2^k
        while (q.mod(TWO).equals(BigInteger.ZERO)) {
            q = q.divide(TWO);
            k++;
        }
        for (int t = 0; t < tests; t ++) {
            //System.out.println("Running test " + t + "/" + tests);

            BigInteger a = uniformRandomInExclusiveRange(BigInteger.ONE, nMinusOne);

            //System.out.println("a=" + a);

            // a^q mod n == 1 ?
            if (a.modPow(q, n).equals(BigInteger.ONE)) {
                return true;
            }
            for (int j = 0; j < k - 1; j++) {
                // a^(q*2^j) mod n == n-1 ?
                if (a.modPow(q.multiply(TWO.pow(j)), n).compareTo(nMinusOne) == 0) {
                    return true;
                }
            }
        }

        return false;
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
