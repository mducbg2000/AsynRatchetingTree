package soict.it2.groupchat.core.tree;

import soict.it2.groupchat.core.serialize.SerializeUtils;
import soict.it2.groupchat.core.crypto.CryptoUtils;
import soict.it2.groupchat.core.crypto.X25519Utils;
import soict.it2.groupchat.core.crypto.XECKeyPair;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.XECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import static java.lang.Math.*;

public class DHTree {

    public static LeafNode buildLeaf(
            String username,
            XECKeyPair adminIdKeys,
            XECPublicKey memberIdKeys,
            XECKeyPair setupKeys,
            XECPublicKey memberEphemeralKey
    ) {

        XECKeyPair keyPair = CryptoUtils.setupExchangeKey(
                adminIdKeys,
                memberIdKeys,
                setupKeys,
                memberEphemeralKey);
        return new LeafNode(username, keyPair);
    }

    /**
     * Group's admin compute {@link KeyPair} for each member
     *
     * @param admin              username of group's admin
     * @param adminIdKey         identity {@link KeyPair} of admin
     * @param setupKey           random {@link KeyPair} for new session
     * @param usernames          list member of group
     * @param theirIdKeys        list identity {@link XECPublicKey} of members
     * @param theirEphemeralKeys list ephemeral {@link XECPublicKey} of members for this session
     * @return list of leaf node in DH tree
     */
    public static List<LeafNode> setupLeavesNode(
            String admin,
            XECKeyPair adminIdKey,
            XECKeyPair setupKey,
            List<String> usernames,
            Map<String, XECPublicKey> theirIdKeys,
            Map<String, XECPublicKey> theirEphemeralKeys
    ) {
        List<LeafNode> leaves = new ArrayList<>();
        leaves.add(new LeafNode(admin, setupKey));
        usernames.remove(admin);
        for (String username : usernames) {
            XECPublicKey memberIdKey = theirIdKeys.get(username);
            XECPublicKey memberEphemeralKey = theirEphemeralKeys.get(username);
            leaves.add(buildLeaf(
                    username,
                    adminIdKey,
                    memberIdKey,
                    setupKey,
                    memberEphemeralKey
            ));
        }
        return leaves;
    }

    /**
     * Build a DH ratcheting tree from leaves
     *
     * @param secretLeaves list of {@link LeafNode}
     * @return root node of the tree, which contain shared secret
     */
    public static Node buildSecretTree(List<LeafNode> secretLeaves) {
        int n = secretLeaves.size();
        if (n == 0) throw new RuntimeException("No leaves");
        if (n == 1) return secretLeaves.get(0);
        int l = leftTreeSize(n);

        Node left = buildSecretTree(secretLeaves.subList(0, l));
        Node right = buildSecretTree(secretLeaves.subList(l, n));

        return new ParentNode(left, right, true);
    }

    /**
     * Build a public tree from a secret tree by remove private key of each node, this public tree will be sent to all member to compute shared secret
     *
     * @param json the secret tree
     * @return root node of public tree
     */
    public static Node buildPublicTree(String json) {
        return SerializeUtils.toTree(json);
    }

    /**
     * Rebuild secret tree from its one secret {@link Node}
     *
     * @param secretNode a node contain private key
     * @return root node of secret tree
     */
    public static Node rebuildSecretTree(Node secretNode) {
        if (secretNode.getKeyPair().getPrivate() == null)
            throw new RuntimeException("Secret node must has private key");
        if (secretNode.getParent() == null) return secretNode;
        secretNode.getParent().computeKeyPair();
        return rebuildSecretTree(secretNode.getParent());
    }

    public static byte[] getGroupKey(Node node) {
        return node.getKeyPair().getPrivate().getScalar().orElseThrow();
    }

    public static LeafNode findLeafNode(String username, Node root) {
        if (root instanceof LeafNode) {
            if (((LeafNode) root).getUsername().equals(username)) return (LeafNode) root;
            return null;
        }
        if (root instanceof ParentNode) {
            LeafNode result = findLeafNode(username, ((ParentNode) root).getLeft());
            if (result != null) return result;
            return findLeafNode(username, ((ParentNode) root).getRight());
        }
        return null;
    }

    /**
     * create new key pair for sending new message and update public key to a path
     * @param child child node contain new key pair
     * @param updatedPath path contain new public key
     * @return root node
     */
    public static void createPublicPath(Node child, Queue<BigInteger> updatedPath) {
        updatedPath.add(child.getKeyPair().getPublic().getU());
        if (child.getParent() == null) return;
        child.getParent().computeKeyPair();
        createPublicPath(child.getParent(), updatedPath);
    }

    public static void updatePath(Node child, Queue<BigInteger> path) {
        BigInteger u = path.peek();
        XECPublicKey publicKey = X25519Utils.fromU(u);
        child.setKeyPair(new XECKeyPair(publicKey, null));

        if (child.getSibling().getKeyPair().getPrivate() != null) {
            rebuildSecretTree(child.getSibling());
            return;
        }

        path.poll();
        updatePath(child.getParent(), path);
    }

    public static int leftTreeSize(int numLeaves) {
        return (int) pow(2, (ceil(log(numLeaves) / log(2)) - 1));
    }


}
