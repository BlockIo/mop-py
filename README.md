MOP-PY
=============

Python script to sweep multisig addresses.

Tested with:

- python 2.7
- python 3.4

#### Installing

1. clone this repository
2. install dependencies: ```pip install base58 ecdsa pycoin requests six```
3. run the script ```python sweep.py [arguments]```

#### Command-line arguments:
```
  -h, --help            show this help message and exit
  -n NETWORK, --network NETWORK
                        Define network code, accepted are: (BTC, DOGE, LTC,
                        BTCTEST, DOGETEST, LTCTEST.
  -s SWEEP_ADDRESS, --sweep-address SWEEP_ADDRESS
                        The address you want to sweep from
  -d DESTINATION_ADDRESS, --destination-address DESTINATION_ADDRESS
                        The address you want to sweep to
  -k KEY, --key KEY     The WIF keys with which to sign the address
  -r REDEEM_SCRIPT, --redeem-script REDEEM_SCRIPT
                        The redeem script for the swept address, enclose in ""
  -p, --push            Push the fully signed tx to the network
  -b, --blockio-sign    Ask block.io to sign this transaction
```

#### Example
```
python sweep.py -n BTC -s 3sFETjxWYKYg8Qk86AQzQo9YK4DGWFiaj7 -d 1UjXYHr6EbbyQoDBP92UkRfZtqTbMzDvGZ \
  -k 5JDkUYhojvGFZzZXQ1inPt2fRBfMBciNbscq5N5LaGUBZvfYN3f -k 5JYB8JPJrHikRPmTPu32mmVV4Mg55WzBZoQzNUG9GmakzoXD86M \
  -r "OP_3 02631A744C676D1020DF2ED2FDE17F77FCFB290A852EB64EAD69D849FB3CBCB728 0396E0E8D557126BACC8E6FF0E8BEE4CE5B391AA88969644671CC92E14E6EC2201 0244F63C9A3B849A5EC99A0440F26972169C68E8148C5B1A8726A8065FE8DC04BF 02B883638120071CC45145B0948852A95DDA85C4E9D068051B83A091B7CFB00539 OP_4 OP_CHECKMULTISIG" \
  -b -p
```

outputs (if there would be any funds)

```
Sweep complete!
Network: BTC
Tx hash: 5565e875fe8a8f357b4133b7c5cfc27c6d54b75a7ca263e72dc13df162591fb9
```
