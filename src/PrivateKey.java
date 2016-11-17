import java.io.Serializable;
import java.math.BigInteger;

public class PrivateKey implements Serializable {
    private BigInteger modulus;
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger prime1;
    private BigInteger prime2;
    private BigInteger exponent1;
    private BigInteger exponent2;
    private BigInteger coefficient;

    public PrivateKey(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger prime1,
                      BigInteger prime2, BigInteger exponent1, BigInteger exponent2, BigInteger coefficient) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.prime1 = prime1;
        this.prime2 = prime2;
        this.exponent1 = exponent1;
        this.exponent2 = exponent2;
        this.coefficient = coefficient;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    public BigInteger getPrime1() {
        return prime1;
    }

    public BigInteger getPrime2() {
        return prime2;
    }

    public BigInteger getExponent1() {
        return exponent1;
    }

    public BigInteger getExponent2() {
        return exponent2;
    }

    public BigInteger getCoefficient() {
        return coefficient;
    }

    @Override
    public String toString() {
        return "Private Key:" +
                "\nn=" + modulus.toString(16) +
                "\ne=" + publicExponent.toString(16) +
                "\nd=" + privateExponent.toString(16) +
                "\np=" + prime1.toString(16) +
                "\nq=" + prime2.toString(16) +
                "\nd mod (p-1)=" + exponent1.toString(16) +
                "\nd mod (q-1)=" + exponent2.toString(16) +
                "\nq^-1 mod p=" + coefficient.toString(16);
    }
}
