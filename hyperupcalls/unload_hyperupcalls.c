#include "hyperupcall.h"

int main() {
    for (int i = 0; i < 8; i++) {
        printf("i: %d\n", i);
        unload_hyperupcall(i);
    }
}