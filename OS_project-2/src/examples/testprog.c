#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  const char hw[] = "echo hello";
  
  pid_t i = exec (hw);
  return (int) i;
  // int exit_val = wait (7);
  // return exit_val;
}
