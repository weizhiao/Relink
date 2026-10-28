#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  int res = system("ps -ef | tail");
  printf("res = %d\n", res);
  sleep(2);
  return 0;
}
