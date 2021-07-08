# Impl m1

## setup

```sh
~/setup_enp9s.bash
```

## dma_read

```sh
./dma_read -r 192.168.10.1 -l 192.168.10.3 -b 02:00 -s 16 -a 0x00022402b
```

## dma_write

```sh
./dma_write -r 192.168.10.1 -l 192.168.10.3 -b 02:00 -s 4 -a 0x000222e52ba0 -p 43981
```
