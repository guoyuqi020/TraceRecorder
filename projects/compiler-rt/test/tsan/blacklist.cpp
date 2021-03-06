// Test blacklist functionality for .

// RUN: echo "fun:*Blacklisted_Thread2*" > %t.blacklist
// RUN: %clangxx_tsan -O1 %s -fsanitize-blacklist=%t.blacklist -o %t && %run %t 2>&1 | FileCheck %s
#include <pthread.h>
#include <stdio.h>

int Global;

void *Thread1(void *x) {
  Global++;
  return NULL;
}

void *Blacklisted_Thread2(void *x) {
  Global--;
  return NULL;
}

int main() {
  pthread_t t[2];
  pthread_create(&t[0], NULL, Thread1, NULL);
  pthread_create(&t[1], NULL, Blacklisted_Thread2, NULL);
  pthread_join(t[0], NULL);
  pthread_join(t[1], NULL);
  fprintf(stderr, "PASS\n");
  return 0;
}

// CHECK-NOT: ThreadSanitizer: data race
