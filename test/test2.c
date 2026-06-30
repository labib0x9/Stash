#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<time.h>

int g[5] = {1, 2, 3, 4, 5};

int main() {

    int s[3] = {100, 200, 300};
    int *h = malloc(4 * sizeof(int));
    if (!h) {
        perror("malloc() failed");
        return 1;
    }
    h[3] = 3000;

    printf("PID = %d\n", getpid());
    printf("While(): Going to sleep....\n");

    time_t start = time(NULL);
    while (time(NULL) - start < 60) {}

    printf("Woke up...\n");
    printf("h[3] = %d\n", h[3]);
    free(h);

    return 0;
}