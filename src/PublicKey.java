import java.math.BigInteger;

public class PublicKey {
    private BigInteger modulus;
    private BigInteger publicExponent;

    public PublicKey(BigInteger modulus, BigInteger publicExponent) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }
}
