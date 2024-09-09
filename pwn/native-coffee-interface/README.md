# Native Coffee Interface [_snakeCTF 2024 Quals_]

**Category**: pwn

## Description

My coffee machine kept getting hacked, so I added a Java wrapper to make it more secure.

## Solution

The challenge consists of a Java program that uses the Java Native Interface (JNI) to call a native library function.

The program simply calls the Java_Chall_runCoffeeMachine function in `libcoffeemachine.so`.
Upon decompiling the binary with Ghidra, the following code is obtained:

```c
void Java_Chall_runCoffeeMachine(long *param_1)
{
  char *pcVar1;
  size_t __n;
  char local_a8 [8];
  long local_a0;
  char local_98 [104];
  long local_30;
  undefined8 local_28;
  undefined8 local_20;
  FILE *local_18;
  int local_10;
  int local_c;

  setvbuf(_stdin,(char *)0x0,2,0);
  setvbuf(_stdout,(char *)0x0,2,0);
  setvbuf(_stderr,(char *)0x0,2,0);
  for (local_c = 0; local_c < 3; local_c = local_c + 1) {
    fwrite("0. Order beverage\n",1,0x12,_stdout);
    fwrite("1. Leave a review\n",1,0x12,_stdout);
    fwrite(&DAT_00102026,1,2,_stdout);
    __isoc99_fscanf(_stdin,&DAT_00102029,&local_30);
    fgetc(_stdin);
    if (local_30 == 0) {
      puts("Which item would you like to order?");
      local_18 = fopen(menuFile,"r");
      while( true ) {
        pcVar1 = fgets(local_98,100,local_18);
        if (pcVar1 == (char *)0x0) break;
        printf("%s",local_98);
      }
      fclose(local_18);
      fwrite(&DAT_00102026,1,2,_stdout);
      __isoc99_fscanf(_stdin,&DAT_00102029,&local_30);
      fgetc(_stdin);
      if ((local_30 < 1) || (3 < local_30)) {
        fwrite("Out of stock.\n\n",1,0xf,_stdout);
      }
      else {
        fwrite("Preparing beverage",1,0x12,_stdout);
        for (local_10 = 0; local_10 < 5; local_10 = local_10 + 1) {
          sleep(1);
          fputc(0x2e,_stdout);
        }
        fwrite("\nEnjoy!\n\n",1,9,_stdout);
      }
    }
    else if (local_30 == 1) {
      puts("Which item would you like to review?");
      local_18 = fopen(menuFile,"r");
      while( true ) {
        pcVar1 = fgets(local_98,100,local_18);
        if (pcVar1 == (char *)0x0) break;
        printf("%s",local_98);
      }
      fclose(local_18);
      printf("> ");
      __isoc99_fscanf(_stdin,&DAT_00102029,&local_a0);
      fgetc(_stdin);
      if ((local_a0 < 0) || (0xe < local_a0)) {
        local_20 = (**(code **)(*param_1 + 0x30))(param_1,"java/lang/IllegalArgumentException");
        (**(code **)(*param_1 + 0x70))(param_1,local_20,"Invalid choice");
      }
      printf("Your review:\n",local_28);
      printf("> ");
      fgets(local_a8,8,_stdin);
      __n = strlen(local_a8);
      strncpy((char *)(local_a0 * 8 + 0x1040f8),local_a8,__n);
      printf("Saved your review at %p\n\n",local_a0 * 8 + 0x1040f8);
    }
    else {
      puts("Invalid choice.\n");
    }
  }
  puts("Goodbye!");
  exit(0);
}
```

The function reads a menu from a file `menuFile`, which is stored in the `.data` section and initially set to `menu.txt`.

The program can be interacted with by choosing one of two actions: ordering a beverage or leaving a review.

When ordering a beverage, the program reads the menu from `menuFile` and prompts the user to choose an item.

When leaving a review, the program also reads the menu from `menuFile` and prompts the user to choose an item, but this time it allows the user to input a review for the selected item, which is saved in a global array of `long` of length 15, stored in the `.bss` section.
If the item selected by the user is outside the range of 0 to 14, the program calls the JNI function `ThrowNew` to throw a new `IllegalArgumentException` with the message "Invalid choice".
This is made possible by the fact that JNI functions are called with an additional parameter of type `JNIEnv*`, which points to the JVM environment and can be used to interact with the JVM itself.
One might expect this call to `ThrowNew` to immediately throw an exception to be handled by the JVM.
However, when exceptions are thrown in JNI code, they are handled by the JVM only upon the return of the JNI function, meaning that the program continues execution even after an invalid index is input.

This behaviour permits a review to be saved at an arbitrary offset from `reviews`, allowing an arbitrary write to occur.
The simplest method of exploiting this to retrieve the flag is by overwriting the `menuFile` variable.
This can be achieved by selecting -16 as the index of the item to be reviewed.
Since the review can be up to 8 bytes long, the string `flag` followed by a null byte can be sent, causing `menuFile` to contain `flag.txt`.

Performing another action will cause the program to read and print the contents of `flag.txt`, which contains the flag:
`snakeCTF{WH3r3_D1D_7H47_3XC3P710N_637_7Hr0WN}`.
