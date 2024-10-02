package merkle;

public class Level {
    private final Digest[] digests;

    public Level(Digest[] digests) {
        this.digests = digests;
    }

    public Digest[] getDigests() {
        return digests;
    }
}
