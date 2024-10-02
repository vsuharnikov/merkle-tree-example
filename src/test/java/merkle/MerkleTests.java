package merkle;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.Collectors;

class MerkleTests {

    private final HexFormat hex = HexFormat.of();

    private final String[] rawTransfersData = new String[]{
            "01442fa84652e2f17b200f5af7c3ed597c320b28861cb26f68ef00000000000000000000000000000000000000000000000000000000000000b1a2bc2ec50000",
            "01442fa84652e2f17b200f5af7c3ed597c320b28861cb26f68ef000000000000000000000000000000000000000000000000000000000000002386f26fc10000",
            "01442fa84652e2f17b200f5af7c3ed597c320b28861cb26f68ef000000000000000000000000000000000000000000000000000000000000002386f26fc10000",
            "01442fa84652e2f17b200f5af7c3ed597c320b28861cb26f68ef00000000000000000000000000000000000000000000000000000000000000b1a2bc2ec50000",
            "014403cf4d50c1450640175edbb0825272985fd392a597bb7605000000000000000000000000000000000000000000000000000000000000004a9b6384488000",
            "01442fa84652e2f17b200f5af7c3ed597c320b28861cb26f68ef00000000000000000000000000000000000000000000000000000000000000038d7ea4c68000",
            "014403cf4d50c1450640175edbb0825272985fd392a597bb760500000000000000000000000000000000000000000000000000000000000000071afd498d0000",
            "014403cf4d50c1450640175edbb0825272985fd392a597bb7605000000000000000000000000000000000000000000000000000000000000000aa87bee538000",
            "014403cf4d50c1450640175edbb0825272985fd392a597bb7605000000000000000000000000000000000000000000000000000000000000000e35fa931a0000"
    };

    private final byte[][] transfersData = Arrays.stream(rawTransfersData)
            .map(hex::parseHex)
            .toArray(byte[][]::new);

    private final Level[] levels = Merkle.mkLevels(transfersData);

    @Test
    void levels() {
        String[] actualStrLevels = Arrays.stream(levels)
                .map(level -> Arrays.stream(level.getDigests())
                        .map(digest -> hex.formatHex(digest.getBytes()))
                        .collect(Collectors.joining(", ")))
                .toArray(String[]::new);

        String[] expectedStrLevels = new String[]{
                "64fb79d48265c90fd7f0b9387c07dbc83effc9500ccdfb2e9a3649e8206d327c",
                "73eecf7fdfffb9bd7a5dbb297602b49d3c427882ac6a33722a9e7799a7948204, cdd91be5ff5c2069e7516fcd288957c2952ad22ba736d49f853c71a6c7793e89",
                "f46652adb1f25b79d1fe8ae9816e9a767a3b92389c97867d11ab11672f273393, 6d42f5233234099bd64514823162066a90ac00d53cc2f9acd80a1fe809aada09, 61d62b28884654e479bfaf55ae86872ffff559ee28164e81ad73a7b32c2a7bff",
                "087928bd3533cb5b86b5a6cdf6c777c25fbff0bde64daaf17b9f1261c3e22d8e, 9f9e2bfeee8b1274428b8f9d0f74193bdd2138b9ccfe2868dc68aa19d1b52b31, 41d7da16fc03c800bf028b5620ab8383214b1be9431a802c35146f9c309387d8, 57d0147b63c9f57f5fe46854cec5351035f289ff3274a4cfb74b3b46d22bc26d, f18100dc180c9a49553141fdd6336584f45e2cd6abb01b3d88de3c8340c2ad5f",
                "ee9b2468c519352007ef2e3bec3b7658cfb781ee04121bfc737bccb4ede1f2c3, 463c02e8e548e9b00ffb660ad583ef6371aabb5d4d00387707013e1a18b72031, 463c02e8e548e9b00ffb660ad583ef6371aabb5d4d00387707013e1a18b72031, ee9b2468c519352007ef2e3bec3b7658cfb781ee04121bfc737bccb4ede1f2c3, 54070e0a3fc7afe3f7fe208c438718a420d4570e2d97e9a9e38f0cb78dda252f, 9ef287bdcae5df65795a7744d8631003d9f0646299163956a918204170347329, e07a633050b66432f9859c999d48f0f67550e18880164f48e5f43054502d5ed4, 35d373372607af77f4cd4697fc7826368293b0afa59925163d2e84ce28f55354, d74c19f1aa645b87f2a3c57af4c101e3ffa13ed7f6bfa94423ba58f5f4ed38a9"
        };

        Assertions.assertArrayEquals(actualStrLevels, expectedStrLevels);
    }

    @Test
    void proofs() {
        var actualProofs = Merkle.mkProofs(levels, 3);
        var actualStrProofs = Arrays.stream(actualProofs)
                .map(digest -> hex.formatHex(digest.getBytes()))
                .toArray(String[]::new);

        var expectedStrProofs = new String[]{
                "463c02e8e548e9b00ffb660ad583ef6371aabb5d4d00387707013e1a18b72031",
                "087928bd3533cb5b86b5a6cdf6c777c25fbff0bde64daaf17b9f1261c3e22d8e",
                "6d42f5233234099bd64514823162066a90ac00d53cc2f9acd80a1fe809aada09",
                "cdd91be5ff5c2069e7516fcd288957c2952ad22ba736d49f853c71a6c7793e89",
        };

        Assertions.assertArrayEquals(actualStrProofs, expectedStrProofs);
    }

}

