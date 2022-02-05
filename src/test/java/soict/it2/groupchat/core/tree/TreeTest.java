package soict.it2.groupchat.core.tree;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import soict.it2.groupchat.core.crypto.CryptoUtils;
import soict.it2.groupchat.core.crypto.X25519Utils;
import soict.it2.groupchat.core.crypto.XECKeyPair;

import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static soict.it2.groupchat.core.serialize.SerializeUtils.*;

class TreeTest {

    String member = "user-4";
    List<LeafNode> leaves;
    XECKeyPair adminIdKey;
    XECKeyPair setupKey;
    Map<String, XECKeyPair> memberIdKeys = new HashMap<>();
    Map<String, XECKeyPair> memberEphemeralKeys = new HashMap<>();

    @BeforeEach
    void setUp() {
        adminIdKey = X25519Utils.newKeyPair();
        setupKey = X25519Utils.newKeyPair();
        List<String> usernames = new ArrayList<>();
        Map<String, XECPublicKey> theirIdKeys = new HashMap<>();
        Map<String, XECPublicKey> theirEphemeralKeys = new HashMap<>();
        for (int i = 0; i < 6; i++) {
            String username = "user-" + i;
            usernames.add(username);
            XECKeyPair idKey = X25519Utils.newKeyPair();
            XECKeyPair ephemeralKey = X25519Utils.newKeyPair();
            theirIdKeys.put(username, idKey.getPublic());
            theirEphemeralKeys.put(username, ephemeralKey.getPublic());
            memberIdKeys.put(username, idKey);
            memberEphemeralKeys.put(username, ephemeralKey);
        }
        leaves = DHTree.setupLeavesNode(
                "admin",
                adminIdKey,
                setupKey,
                usernames,
                theirIdKeys,
                theirEphemeralKeys
        );
    }

    @Test
    void testLeftTreeSize() {
        int n = DHTree.leftTreeSize(1);
        assertEquals(0, n);
    }

    @Test
    void testSerializationTree() {
        Node root = DHTree.buildSecretTree(leaves);
        String json = toJson(root);
        Node publicRoot = toTree(json);
        String jsonTest = toJson(publicRoot);
        assertEquals(json, jsonTest);
    }

    @Test
    void testRebuildSecretTree() {
        Node secretTree = DHTree.buildSecretTree(leaves);
        String json = toJson(secretTree);
        Node publicTree = DHTree.buildPublicTree(json);
        LeafNode secretLeaf = DHTree.findLeafNode(member, publicTree);
        XECKeyPair keyPair = CryptoUtils.recomputeExchangeKey(
                memberIdKeys.get(member),
                adminIdKey.getPublic(),
                memberEphemeralKeys.get(member),
                setupKey.getPublic()
        );
        secretLeaf.setKeyPair(keyPair);
        publicTree = DHTree.rebuildSecretTree(secretLeaf);
        assertArrayEquals(
                DHTree.getGroupKey(secretTree),
                DHTree.getGroupKey(publicTree)
        );
    }

    @Test
    void testUpdateKey() {
        // admin setup new tree
        Node secretTree = DHTree.buildSecretTree(leaves);
        // serialized it to json string for sending to another
        String json = toJson(secretTree);

        // user-2 phase
        // user-2 in group receive a public tree
        Node tree2 = DHTree.buildPublicTree(json);
        // user-2 find his leaf node in the tree
        LeafNode secretLeaf2 = DHTree.findLeafNode("user-2", tree2);
        // user-2 generate new key pair to send message
        XECKeyPair newEphemeralKey2 = X25519Utils.newKeyPair();
        // user-2 rebuild the secret tree base on new key pair and create a update path
        secretLeaf2.setKeyPair(newEphemeralKey2);
        Queue<BigInteger> path = new LinkedList<>();
        DHTree.createPublicPath(secretLeaf2, path);

        // user-4 receive a public tree
        Node publicTree4 = DHTree.buildPublicTree(json);
        LeafNode secretLeaf4 = DHTree.findLeafNode("user-4", publicTree4);
        XECKeyPair keyPair = CryptoUtils.recomputeExchangeKey(
                memberIdKeys.get("user-4"),
                adminIdKey.getPublic(),
                memberEphemeralKeys.get("user-4"),
                setupKey.getPublic()
        );
        secretLeaf4.setKeyPair(keyPair);
        // build secret tree from leaf of user-4
        Node tree4 = DHTree.rebuildSecretTree(secretLeaf4);

        // find node of user-2
        LeafNode leaf2 = DHTree.findLeafNode("user-2", tree4);
        // update the path
        DHTree.updatePath(leaf2, path);

        // compare share secret between tree of user-2 and updated tree of user-4
        assertArrayEquals(
                DHTree.getGroupKey(tree2),
                DHTree.getGroupKey(publicTree4)
        );
    }
}