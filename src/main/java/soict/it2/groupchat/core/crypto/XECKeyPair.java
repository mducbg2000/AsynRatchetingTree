package soict.it2.groupchat.core.crypto;

import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;

public class XECKeyPair {
    private final XECPublicKey publicKey;
    private final XECPrivateKey privateKey;

    public XECKeyPair(XECPublicKey publicKey, XECPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public XECPublicKey getPublic() {
        return publicKey;
    }

    public XECPrivateKey getPrivate() {
        return privateKey;
    }
}
