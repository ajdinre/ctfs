I got 2 files, one is for encryption and the second one is the encrypted flag:
```
$ file rev_simpleencryptor/*
rev_simpleencryptor/encrypt:  ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0bddc0a794eca6f6e2e9dac0b6190b62f07c4c75, for GNU/Linux 3.2.0, not stripped
rev_simpleencryptor/flag.enc: data
```

ghidra gave me this:
```
undefined8 main(void)

{
  int iVar1;
  time_t tVar2;
  long in_FS_OFFSET;
  uint local_40;
  uint local_3c;
  long local_38;
  FILE *local_30;
  size_t local_28;
  void *local_20;
  FILE *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_30 = fopen("flag","rb");
  fseek(local_30,0,2);
  local_28 = ftell(local_30);
  fseek(local_30,0,0);
  local_20 = malloc(local_28);
  fread(local_20,local_28,1,local_30);
  fclose(local_30);
  tVar2 = time((time_t *)0x0);
  local_40 = (uint)tVar2;
  srand(local_40);
  for (local_38 = 0; local_38 < (long)local_28; local_38 = local_38 + 1) {
    iVar1 = rand();
    *(byte *)((long)local_20 + local_38) = *(byte *)((long)local_20 + local_38) ^ (byte)iVar1;
    local_3c = rand();
    local_3c = local_3c & 7;
    *(byte *)((long)local_20 + local_38) =
         *(byte *)((long)local_20 + local_38) << (sbyte)local_3c |
         *(byte *)((long)local_20 + local_38) >> 8 - (sbyte)local_3c;
  }
  local_18 = fopen("flag.enc","wb");
  fwrite(&local_40,1,4,local_18);
  fwrite(local_20,1,local_28,local_18);
  fclose(local_18);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

after cleaning up:
```

undefined8 main(void)

{
  // ***** vars *****
  int rand_value;
  time_t curr_time;
  long in_FS_OFFSET;
  uint rand_seed;
  uint local_3c;
  long i;
  FILE *raw_flag_file;
  size_t raw_flag_size;
  void *flag_data;
  FILE *encrypted_flag_fp;
  long local_10;
  
  // ***** stack canary *****
  canary = *(long *)(in_FS_OFFSET + 0x28);

  // ***** read flag *****
  raw_flag_file = fopen("flag","rb");
  fseek(raw_flag_file,0,2);
  raw_flag_size = ftell(raw_flag_file);
  fseek(raw_flag_file,0,0);
  flag_data = malloc(raw_flag_size);
  fread(flag_data,raw_flag_size,1,raw_flag_file);
  fclose(raw_flag_file);

  // ***** init rand *****
  curr_time = time((time_t *)0x0);
  rand_seed = (uint)curr_time;
  srand(rand_seed);

  // ***** encrypt *****
  for (i = 0; i < (long)raw_flag_size; i = i + 1) {
    rand_value_1 = rand();
    *(byte *)((long)flag_data + i) = *(byte *)((long)flag_data + i) ^ (byte)rand_value_1; // encrypted_char = flag_char ^ rand_value_1
    rand_value_2 = rand();
    rand_value_2 = rand_value_2 & 7;
    *(byte *)((long)flag_data + i) =
         *(byte *)((long)flag_data + i) << (sbyte)random_value_2 |
         *(byte *)((long)flag_data + i) >> 8 - (sbyte)random_value2;
    // encrypted_char = encrypted_char << random_value_2 | encrypted_char >> 8 - random_value_2
  }

  // ***** save flag *****
  encrypted_flag_fp = fopen("flag.enc","wb");
  fwrite(&rand_seed,1,4,encrypted_flag_fp);
  fwrite(flag_data,1,raw_flag_size,encrypted_flag_fp);
  fclose(encrypted_flag_fp);


  // ***** stack canary *****
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

I wrote script to reverse the algo in decrypt.py  
