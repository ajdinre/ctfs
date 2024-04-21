coudn't run the binary on my mac, since it gave me some rosetta errors. I imported it in ghidra, and main was looking wierd:
```
void main(void)

{
  long in_FS_OFFSET;
  sigaction local_a8;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  memset(&local_a8,0,0x98);
  sigemptyset(&local_a8.sa_mask);
  local_a8.__sigaction_handler.sa_handler = segill_sigaction;
  local_a8.sa_flags = 4;
  sigaction(4,&local_a8,(sigaction *)0x0);
  do {
    invalidInstructionException();
  } while( true );
}
```

`invalidInstructionException` was caused by ud2 instruction, and bytes after what werent disassembled. I selected the bytes right after the main function and ran disassembly on them. I found a strcmp function call and found a string "Itz"

```
void UndefinedFunction_0010132f(void)

{
  int iVar1;
  long unaff_RBP;
  
  iVar1 = strncmp(*(char **)(*(long *)(unaff_RBP + -0xb0) + 8),"Itz",3);
  if (iVar1 == 0) {
    do {
      invalidInstructionException();
    } while( true );
  }
  do {
    invalidInstructionException();
  } while( true );
}
```

I found where the string was defined, and found the rest of the flag:
```
                             DAT_0010201b                                    XREF[1]:     00101342(*)  
        0010201b 49              ??         49h    I
        0010201c 74              ??         74h    t
        0010201d 7a              ??         7Ah    z
        0010201e 00              ??         00h
                             DAT_0010201f                                    XREF[1]:     00101372(*)  
        0010201f 5f              ??         5Fh    _
        00102020 30              ??         30h    0
        00102021 6e              ??         6Eh    n
        00102022 00              ??         00h
                             DAT_00102023                                    XREF[1]:     001013a2(*)  
        00102023 4c              ??         4Ch    L
        00102024 79              ??         79h    y
        00102025 5f              ??         5Fh    _
        00102026 00              ??         00h
                             DAT_00102027                                    XREF[1]:     001013ce(*)  
        00102027 55              ??         55h    U
        00102028 44              ??         44h    D
        00102029 32              ??         32h    2
        0010202a 00              ??         00h
```
