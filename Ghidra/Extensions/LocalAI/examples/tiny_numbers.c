/*
 * SPDX-License-Identifier: CC0-1.0
 *
 * LocalAI Ghidra test program.
 * Dedicated to the public domain under CC0 1.0.
 */

#include <stdio.h>

static int adjust_value(int value) {
    if (value < 0) {
        return 0;
    }

    if (value > 100) {
        return 100;
    }

    return value;
}

static int mix_score(int left, int right) {
    int a = adjust_value(left);
    int b = adjust_value(right);
    return (a * 3) + (b * 2);
}

int main(void) {
    int result = mix_score(12, 34);
    printf("score=%d\n", result);
    return result == 104 ? 0 : 1;
}
