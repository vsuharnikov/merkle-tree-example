package merkle;

import org.bouncycastle.jcajce.provider.digest.Blake2b;

import java.security.MessageDigest;
import java.util.Arrays;

public class Merkle {

    private static final Digest EMPTY = digest(new byte[]{0});
    private static final Level[] EMPTY_LEVELS = new Level[]{new Level(new Digest[]{EMPTY})};

    public static Level[] mkLevels(byte[][] data) {
        if (data.length == 0) {
            return EMPTY_LEVELS;
        }

        Level[] levels = new Level[1];
        Digest[] currentLevel = Arrays.stream(data).map(Merkle::digest).toArray(Digest[]::new);
        levels[0] = new Level(currentLevel);

        while (currentLevel.length > 1) {
            Digest[] nextLevel = new Digest[(currentLevel.length + 1) / 2];
            for (int i = 0; i < currentLevel.length; i += 2) {
                Digest left = currentLevel[i];
                Digest right = (i + 1 < currentLevel.length) ? currentLevel[i + 1] : EMPTY;
                nextLevel[i / 2] = digest(concat(left.getBytes(), right.getBytes()));
            }
            Level[] newLevels = new Level[levels.length + 1];
            System.arraycopy(levels, 0, newLevels, 1, levels.length);

            newLevels[0] = new Level(nextLevel);
            levels = newLevels;
            currentLevel = nextLevel;
        }

        return levels;
    }

    public static Digest[] mkProofs(Level[] levels, int dataIndex) {
        Digest[] proofs = new Digest[levels.length - 1];
        int idx = dataIndex;

        for (int i = levels.length - 1; i >= 1; i--) {
            Digest[] level = levels[i].getDigests();

            Digest proof;
            if (isLeft(idx)) {
                proof = (idx + 1 == level.length) ? EMPTY : level[idx + 1];
            } else {
                proof = level[idx - 1];
            }

            proofs[levels.length - i - 1] = proof;
            idx /= 2;
        }

        return proofs;
    }

    private static boolean isLeft(int i) {
        return i % 2 == 0;
    }

    public static byte[] hash(byte[] input) {
        MessageDigest digest = new Blake2b.Blake2b256();
        return digest.digest(input);
    }

    private static Digest digest(byte[] input) {
        return new Digest(input, Merkle::hash);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }
}
