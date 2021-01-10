package se.deogun.aes.modes;

import org.junit.jupiter.api.Test;

import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.UUID;

import static java.util.Arrays.copyOfRange;
import static org.apache.commons.lang3.StringUtils.repeat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static se.deogun.aes.modes.InitVector.DataSelectionStrategy.*;

class InitVectorTest {
    @Test
    void should_reject_too_little_data() {
        assertThrows(IllegalArgumentException.class, () -> new InitVector(repeat("X", 11)));
    }

    @Test
    void should_hit_upper_bound() {
        assertThrows(IllegalArgumentException.class, () -> new InitVector(repeat("X", 4097)));
    }

    @Test
    void should_accept_12_bytes_of_data() {
        assertDoesNotThrow(() -> new InitVector(repeat("X", 12)));
    }

    @Test
    void should_accept_UUID() {
        assertDoesNotThrow(() -> new InitVector(UUID.randomUUID().toString()));
    }

    @Test
    void should_select_first_vector_bytes() {
        byte[] data = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        assertTrue(Arrays.equals(copyOfRange(data,0, 12), new InitVector(new String(data), FIRST_12_BYTES).value()));
    }

    @Test
    void should_select_mid_vector_bytes() {
        byte[] data = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        assertTrue(Arrays.equals(copyOfRange(data,1, 13), new InitVector(new String(data), MID_12_BYTES).value()));
    }

    @Test
    void should_select_last_vector_bytes() {
        byte[] data = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        assertTrue(Arrays.equals(copyOfRange(data,3, 15), new InitVector(new String(data), LAST_12_BYTES).value()));
    }

    @Test
    void should_accept_uuid() {
        final var data = UUID.randomUUID();
        assertTrue(Arrays.equals(copyOfRange(data.toString().replace("-","").getBytes(),0, 12), new InitVector(data).value()));
    }

    @Test
    void should_not_allow_externalization() {
        final var nonce = new InitVector(UUID.randomUUID().toString());

        assertThrows(UnsupportedOperationException.class, () -> nonce.writeExternal(mock(ObjectOutput.class)));
        assertThrows(UnsupportedOperationException.class, () -> nonce.readExternal(mock(ObjectInput.class)));
    }

    @Test
    void should_not_print_value_in_toString() {
        final var result = new InitVector(repeat("X", 12)).toString();

        assertEquals("***** SENSITIVE VALUE *****", result);
    }

    @SuppressWarnings("ALL")
    @Test
    void should_not_respect_equals() {
        final InitVector vector = new InitVector(UUID.randomUUID().toString());

        assertFalse(vector.equals(vector));
        assertFalse(vector.equals(new InitVector(UUID.randomUUID().toString())));
    }

    @Test
    void should_not_respect_hash_code() {
        final InitVector vector = new InitVector(UUID.randomUUID().toString());

        assertEquals(0, vector.hashCode());
        assertEquals(vector.hashCode(), new InitVector(UUID.randomUUID().toString()).hashCode());
    }
}