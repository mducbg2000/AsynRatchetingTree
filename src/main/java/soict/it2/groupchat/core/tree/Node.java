package soict.it2.groupchat.core.tree;

import soict.it2.groupchat.core.crypto.XECKeyPair;


public abstract class Node {

    private transient XECKeyPair keyPair;
    private ParentNode parent;
    private Node sibling;

    public XECKeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(XECKeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public ParentNode getParent() {
        return parent;
    }

    public void setParent(ParentNode parent) {
        this.parent = parent;
    }

    public Node getSibling() {
        return sibling;
    }

    public void setSibling(Node sibling) {
        this.sibling = sibling;
    }

    abstract int numLeaves();
}
