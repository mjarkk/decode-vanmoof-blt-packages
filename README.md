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

### `-hideChallenges`

Hide challenge requests and hide the challenge / nonce inside the write requests

### `-showOnlyFirstPartOfUuid`

Only shows the first part of UUIDs as the remainder of the uuid always seems to stays the same.

### Obtain bikeId and encryptionKey

1. Login to [mooovy.app](https://mooovy.app/) using chrome
2. Open the developer tools (F12)
3. Go to the Application tab
4. Go to the Local Storage tab and select Select the `https://mooovy.app` entry
5. Click on `vm-bike-credentials`
6. Copy the following values:
   - `encryptionKey` = `encryptionKey`
   - `mac` = `bikeId`

![HowTo](/howto.png?raw=true "Chrome browser how to What to look for in chrome")

### How to sniff bluetooth?

#### Host: Macos, Client: Macos & IOS

1. Download [XCode Additional Tools](https://developer.apple.com/xcode/resources/)
2. Open `Hardware > PacketLogger`
3. Start logging (Make sure your bike was not connected to your **device** at the moment you started logging!)
4. In the menu bar select `File > Export > BTSnoop..` or <kbd>⇧ Shift</kbd> + <kbd>⌘ Command</kbd> + <kbd>E</kbd>
