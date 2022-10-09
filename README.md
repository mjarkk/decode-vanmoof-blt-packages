## Decode Bluetooth sniffs from and to a VanMoof bike

**NOT** an offical VanMoof service/product!

![Preview](/preview.png?raw=true "Preview")

### Usage

```sh
# Make sure you have installed golang and have setup your $GOPATH correctly
go install github.com/mjarkk/decode-vanmoof-blt-packages

decode-vanmoof-blt-packages \
    -encryptionKey "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    -bikeId "34 56 78 9a bc de" \
    -file "bt_snoop.log"
```

### Arguments

#### `-file`

This is the bluetooth sniff file you want to inspect.

This file should be in the BTSnoop file format.

#### `-bikeId`

This should be the id of your bike.

This value can be obtained from the vanmoof api.

#### `-encryptionKey`

This should be the encryption key of your bike

This value can be obtained from the vanmoof api.
