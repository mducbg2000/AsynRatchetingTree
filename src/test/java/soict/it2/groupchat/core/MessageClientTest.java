package soict.it2.groupchat.core;

import org.junit.jupiter.api.Test;

import java.security.interfaces.XECPublicKey;

import static org.junit.jupiter.api.Assertions.*;

class MessageClientTest {

    @Test
    void testChat() {
        MessageClient admin = new MessageClient("admin");
        MessageClient alice = new MessageClient("alice");
        MessageClient bob = new MessageClient("bob");
        MessageClient charlie = new MessageClient("charlie");
        MessageClient duke = new MessageClient("duke");

        admin.creatNewGroup(0);

        XECPublicKey alicePubKey = alice.joinGroup(0);
        XECPublicKey bobPubKey = bob.joinGroup(0);
        XECPublicKey charliePubKey = charlie.joinGroup(0);
        XECPublicKey dukePubKey = duke.joinGroup(0);

        admin.addMember(0, "alice",
                alice.getIdKey(), alicePubKey);
        admin.addMember(0, "bob",
                bob.getIdKey(), bobPubKey);
        admin.addMember(0, "charlie",
                charlie.getIdKey(), charliePubKey);
        String setupMsg = admin.addMember(0, "duke",
                duke.getIdKey(), dukePubKey);

        alice.receiveSetupMessage(setupMsg);
        bob.receiveSetupMessage(setupMsg);
        charlie.receiveSetupMessage(setupMsg);
        duke.receiveSetupMessage(setupMsg);

        String plainMsg = "Hello group";

        String message = duke.sendMessage(0, plainMsg);

        String decrypted = alice.receiveMessage(message);

        String anotherMsg = duke.sendMessage(0, "Hê hê");

        String anotherDecrypted = bob.receiveMessage(anotherMsg);

        assertEquals(plainMsg, decrypted);

        assertEquals("Hê hê", anotherDecrypted);
    }

}