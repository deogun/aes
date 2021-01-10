package se.deogun.aes.modes.gcm;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AADTest {
    @Test
    void should_not_accept_empty_aad() {
        assertThrows(IllegalArgumentException.class, () -> new AAD(""));
    }

    @Test
    void should_not_allow_modification() {
        final var aad = new AAD("hello");
        final var value = aad.value();
        value[0]++;

        assertEquals("hello", new String(aad.value()));
        assertFalse(Arrays.equals(value, aad.value()));
    }

    @Test
    void should_hit_upper_bound() {
        assertThrows(IllegalArgumentException.class, () -> new AAD(StringUtils.repeat("X", 8193)));
    }
}