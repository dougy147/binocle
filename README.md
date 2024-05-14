Another experiment copying [`binwalk`](https://github.com/ReFirmLabs/binwalk).

```console
$ gcc binocle.c -o binocle -lm
$ ./binocle file.bin

DECIMAL         HEXADECIMAL     ENTROPY
--------------------------------------------------------------------------------
0               0x0             Falling entropy edge (0.549106)

DECIMAL         HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0               0x0             Script or data to be passed to the program following the shebang (#!)
```

This project is just an excuse to learn C. See [binrub](https://github.com/dougy147/binrub) for a Ruby version.
