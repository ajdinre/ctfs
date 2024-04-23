# Exatlon

Tried using Ghidra to reverse engineer but coudn't get anything useful, it looked like a lot of the data was repeating `0x00`. After running binwalk on it found something useful.


```
% binwalk exatlon_v1 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB executable, AMD x86-64, version 1 (GNU/Linux)
272           0x110           ELF, 64-bit LSB processor-specific, (GNU/Linux)
596117        0x91895         Copyright string: "Copyright (C) 1996-2018 the UPX Team. All Rights Reserved. $"
```

UPX is an ELF Packer. I unpacked the binary and started reversing again.

```
root@e55617cd144b:/ctf# upx -d exatlon_v1 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   2202568 <-    709524   32.21%   linux/amd64   exatlon_v1

Unpacked 1 file.
```


After finding main:
```

undefined4 main(void)

{
  bool bVar1;
  basic_ostream *pbVar2;
  undefined4 unaff_R12D;
  basic_string abStack_58 [32];
  basic_string abStack_38 [32];
  
  do {
    std::operator<<((basic_ostream *)&std::cout,"\n");
    std::operator<<((basic_ostream *)&std::cout,&DAT_0054b018);
    std::operator<<((basic_ostream *)&std::cout,&DAT_0054b0d8);
    sleep(1);
    std::operator<<((basic_ostream *)&std::cout,&DAT_0054b1a8);
    std::operator<<((basic_ostream *)&std::cout,&DAT_0054b260);
    sleep(1);
    std::operator<<((basic_ostream *)&std::cout,&DAT_0054b320);
    sleep(1);
    std::operator<<((basic_ostream *)&std::cout,&DAT_0054b400);
    sleep(1);
    std::__cxx11::basic_string<>::basic_string();
                    /* try { // try from 00404cfe to 00404dce has its CatchHandler @ 00404def */
    std::operator<<((basic_ostream *)&std::cout,"[+] Enter Exatlon Password  : ");
    std::operator>>((basic_istream *)&std::cin,abStack_58);
    exatlon(abStack_38);
    bVar1 = std::operator==(abStack_38,
                            "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000 "
                           );
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_38);
    if (bVar1) {
      pbVar2 = std::operator<<((basic_ostream *)&std::cout,"[+] Looks Good ^_^ \n\n\n");
      std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar2,std::endl<>);
      unaff_R12D = 0;
      bVar1 = false;
    }
    else {
      bVar1 = std::operator==(abStack_58,"q");
      if (bVar1) {
        unaff_R12D = 0;
        bVar1 = false;
      }
      else {
        pbVar2 = std::operator<<((basic_ostream *)&std::cout,"[-] ;(\n");
        std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar2,std::endl<>);
        bVar1 = true;
      }
    }
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_58);
  } while (bVar1);
  return unaff_R12D;
}
```

so it's loading the password and calling a `exatlon()` function on another variable

```
    std::operator<<((basic_ostream *)&std::cout,"[+] Enter Exatlon Password  : ");
    std::operator>>((basic_istream *)&std::cin,abStack_58);
    exatlon(abStack_38);
```

That function seems to go in a for loop, I clean it up a bit

```
basic_string * exatlon(basic_string *param_1)

{
  bool exit_condition;
  char *char_addr;
  undefined8 end_i;
  undefined8 start_i;
  allocator<char> local_69;
  basic_string new_string [32];
  __cxx11 shifter_char [39];
  char curr_char;
  
  std::allocator<char>::allocator();
                    /* try { // try from 00404ae8 to 00404aec has its CatchHandler @ 00404bc1 */
  std::__cxx11::basic_string<>::basic_string((char *)param_1,(allocator *)&DAT_0054b00c);
  std::allocator<char>::~allocator(&local_69);
  start_i = std::__cxx11::basic_string<>::begin();
  end_i = std::__cxx11::basic_string<>::end();
  while( true ) {
    exit_condition =
         __gnu_cxx::operator!=((__normal_iterator *)&start_i,(__normal_iterator *)&end_i);
    if (!exit_condition) break;
    char_addr = (char *)__gnu_cxx::__normal_iterator<>::operator*((__normal_iterator<> *)&start_i);
    curr_char = *char_addr;
                    /* try { // try from 00404b63 to 00404b67 has its CatchHandler @ 00404bfd */
    std::__cxx11::to_string(shifter_char,(int)curr_char << 4);
                    /* try { // try from 00404b7d to 00404b81 has its CatchHandler @ 00404bec */
    std::operator+(new_string,shifter_char," ");
                    /* try { // try from 00404b93 to 00404b97 has its CatchHandler @ 00404bdb */
    std::__cxx11::basic_string<>::operator+=((basic_string<> *)param_1,new_string);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)new_string);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)shifter_char);
    __gnu_cxx::__normal_iterator<>::operator++((__normal_iterator<> *)&start_i);
  }
  return param_1;
}

```

so some chars are shifted left by 4 and there is a space added. This looks like a bad hashing function. In `main` we had the value
```
    bVar1 = std::operator==(local_38,
                            "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000 "
                           );
```
so this is the result of our bad hashing function. I reversed the hash using python.

