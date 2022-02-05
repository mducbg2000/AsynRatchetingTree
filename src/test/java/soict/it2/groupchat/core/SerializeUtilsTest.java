package soict.it2.groupchat.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import soict.it2.groupchat.core.crypto.X25519Utils;
import soict.it2.groupchat.core.crypto.XECKeyPair;
import soict.it2.groupchat.core.serialize.SerializeUtils;
import soict.it2.groupchat.core.tree.Node;
import soict.it2.groupchat.core.serialize.TreeSerialize;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.XECPublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class SerializeUtilsTest {

    @Test
    void testQueueToJson() {
        Queue<BigInteger> queue = new LinkedList<>();
        queue.add(BigInteger.valueOf(123456789));
        queue.add(BigInteger.valueOf(987654321));
        queue.add(BigInteger.valueOf(741852963));
        queue.add(BigInteger.valueOf(369258147));

        String json = SerializeUtils.toJson(queue);

        Queue<BigInteger> result = SerializeUtils.toQueue(json);

        result.poll();

        assertEquals(0, Objects.requireNonNull(result.poll()).compareTo(BigInteger.valueOf(987654321)));
    }


    @Test
    void toMap() {
        Map<String, XECPublicKey> map = new HashMap<>();
        XECKeyPair keyPair1 = X25519Utils.newKeyPair();
        XECKeyPair keyPair2 = X25519Utils.newKeyPair();
        XECKeyPair keyPair3 = X25519Utils.newKeyPair();
        XECKeyPair keyPair4 = X25519Utils.newKeyPair();

        map.put("user1", keyPair1.getPublic());
        map.put("user2", keyPair2.getPublic());
        map.put("user3", keyPair3.getPublic());
        map.put("user4", keyPair4.getPublic());

        String json = SerializeUtils.toJson(map);

        System.out.println(json);

        Map<String, XECPublicKey> deserialize = SerializeUtils.toMap(json);

        assertArrayEquals(
                map.get("user4").getEncoded(),
                deserialize.get("user4").getEncoded()
        );
    }
}