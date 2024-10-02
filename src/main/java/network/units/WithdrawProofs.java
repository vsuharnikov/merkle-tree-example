package network.units;

import merkle.Digest;
import merkle.Level;
import merkle.Merkle;

import java.util.Arrays;

public class WithdrawProofs {
    public static Digest[] create(byte[][] data, int dataIndex) {
        if (data.length < 1024) {
            byte[][] paddedData = new byte[1024][];
            System.arraycopy(data, 0, paddedData, 0, data.length);
            Arrays.fill(paddedData, data.length, 1024, new byte[]{0});
            data = paddedData;
        }

        Level[] levels = Merkle.mkLevels(data);
        return Merkle.mkProofs(levels, dataIndex);
    }
}
