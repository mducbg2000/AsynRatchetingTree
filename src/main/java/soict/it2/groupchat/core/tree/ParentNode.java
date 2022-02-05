package soict.it2.groupchat.core.tree;

import soict.it2.groupchat.core.crypto.X25519Utils;
import soict.it2.groupchat.core.crypto.XECKeyPair;

import java.security.KeyPair;
import java.security.interfaces.XECPublicKey;

public class ParentNode extends Node {

    private final Node left;
    private final Node right;

    public ParentNode(Node left, Node right, boolean isSecret) {
        this.left = left;
        this.right = right;
        left.setParent(this);
        left.setSibling(right);
        right.setParent(this);
        right.setSibling(left);
        if (isSecret) computeKeyPair();
    }

    public Node getLeft() {
        return left;
    }

    public Node getRight() {
        return right;
    }

    @Override
    int numLeaves() {
        return left.numLeaves() + right.numLeaves();
    }

    public void computeKeyPair() {
        if (left.getKeyPair().getPrivate() != null) {
            computeKeyPair(left.getKeyPair(), (XECPublicKey) right.getKeyPair().getPublic());
        } else {
            computeKeyPair(right.getKeyPair(), (XECPublicKey) left.getKeyPair().getPublic());
        }
    }

    private void computeKeyPair(XECKeyPair keyPair, XECPublicKey publicKey) {
        byte[] rawPrivateKey = X25519Utils.exchange(keyPair, publicKey);
        this.setKeyPair(X25519Utils.fromPrivateKey(rawPrivateKey));
    }

    public static ParentNode fromSecretParent(ParentNode secretParent, Node publicLeft, Node publicRight) {
        ParentNode publicNode = new ParentNode(publicLeft, publicRight, false);
        publicNode.setKeyPair(new XECKeyPair(secretParent.getKeyPair().getPublic(), null));
        return publicNode;
    }
}
