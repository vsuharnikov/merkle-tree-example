package merkle;

import java.util.Arrays;
import java.util.function.Function;

public class Digest {
    private final byte[] bytes;

    public Digest(byte[] bytes, Function<byte[], byte[]> hashFunction) {
        this.bytes = hashFunction.apply(bytes);
    }

    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public String toString() {
        return Arrays.toString(bytes);
    }
}
