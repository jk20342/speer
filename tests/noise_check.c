#include "speer_internal.h"
#include <stdio.h>

int main(void) {
    uint8_t a_seed[32] = {8}, b_seed[32] = {0};
    uint8_t a_pub[32], a_priv[32], b_pub[32], b_priv[32];
    speer_generate_keypair(a_pub, a_priv, a_seed);
    speer_generate_keypair(b_pub, b_priv, b_seed);
    
    speer_handshake_t a, b;
    uint8_t m1[32], m2[80], m3[48];
    uint8_t a_send[32], a_recv[32], b_send[32], b_recv[32];
    
    speer_noise_xx_init(&a, a_pub, a_priv);
    speer_noise_xx_init(&b, b_pub, b_priv);
    
    if (speer_noise_xx_write_msg1(&a, m1) != 0) return puts("write m1 failed"), 1;
    if (speer_noise_xx_read_msg1(&b, m1) != 0) return puts("read m1 failed"), 1;
    if (speer_noise_xx_write_msg2(&b, m2) != 0) return puts("write m2 failed"), 1;
    uint8_t saved_b_key[32];
    memcpy(saved_b_key, b.send_key, 32);
    if (speer_noise_xx_read_msg2(&a, m2) != 0) return puts("read m2 failed"), 1;
    if (speer_noise_xx_write_msg3(&a, m3) != 0) return puts("write m3 failed"), 1;
    if (speer_noise_xx_read_msg3(&b, m3) != 0) return puts("read m3 failed"), 1;
    
    speer_noise_xx_split(&a, a_send, a_recv);
    speer_noise_xx_split(&b, b_recv, b_send);
    
    int ok = memcmp(a_send, b_recv, 32) == 0 && memcmp(a_recv, b_send, 32) == 0;
    printf("noise xx: %s\n", ok ? "ok" : "fail");
    return ok ? 0 : 1;
}
