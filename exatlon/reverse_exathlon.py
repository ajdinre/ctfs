hash_value = '1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000'
hash_value = hash_value.split(' ')
hash_value = [int(x) for x in hash_value]

for chunk in hash_value:
   shifted = chunk >> 4
   print(chr(shifted), end='')
