### ./doca_aes_gcm_encrypt -f ../in.txt -s 1MB 
-f -s 参数必写
1MB：6800BM/S   512KB: 2900MB/S
最多只能到1.9MB≈1945KB

### loop:
循环里直接提交 size<1MB 的文件数据，然后等待回收，再提交...