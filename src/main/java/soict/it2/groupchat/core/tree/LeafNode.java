package soict.it2.groupchat.core.tree;

import soict.it2.groupchat.core.crypto.XECKeyPair;

public class LeafNode extends Node {

    private final String username;

    public LeafNode(String username, XECKeyPair keyPair) {
        this.setKeyPair(keyPair);
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    @Override
    int numLeaves() {
        return 1;
    }
}
