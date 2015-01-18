import io
import json
import six
import base58
import math
import requests
import argparse

from decimal import *
from ecdsa import SigningKey, SECP256k1, util
from hashlib import sha256
from binascii import hexlify, unhexlify
from collections import namedtuple

from pycoin.serialize import b2h, h2b, h2b_rev, b2h_rev
from pycoin.tx.script import tools
from pycoin.tx import Tx, Spendable, TxOut

# set decimal precision for Decimal to 64bit
getcontext().prec = 64

# size estimation constants
TxComponents = namedtuple('TxComponents',
                           ('version', 'in_count', 'out_count', 'locktime', 'in_prevout',
                            'in_scriptlen', 'in_ops', 'in_m', 'in_seq', 'out_value', 'out_scriptlen', 'out_scriptsize'))
TX_COMPONENTS = TxComponents(4,3,3,4,36,4,3,73,4,8,1,35)

# fee estimation constants
NETWORK_FEES = {"BTC": Decimal(0.0001), "DOGE": Decimal(1), "LTC": Decimal(0.001), "BTCTEST": Decimal(0.0001), "DOGETEST": Decimal(1), "LTCTEST": Decimal(0.001)}

def sochain_get_unspents(network, address):
    #TODO error handling
    url = "https://chain.so/api/v2/get_tx_unspent/{0}/{1}".format(network, address)

    session = requests.session()
    response = session.get(url)
    response = response.json().get("data", {})
    session.close()

    return response

# push a tx to chain.so
def sochain_pushtx(network, tx):
    #TODO error handling
    url = "https://chain.so/api/v2/send_tx/{0}".format(network)
    data = {"tx_hex": tx.as_hex()}

    session = requests.session()
    response = session.post(url, data=data)
    response = response.json().get("data", {})
    session.close()

    return response

# taken from block_io lib
def compress_pubkey(pubkey):
    x = pubkey[:32]
    y = pubkey[33:64]
    y_int = 0
    for c in six.iterbytes(y):
        y_int = 256 * y_int + c
    return six.int2byte(2+(y_int % 2)) + x

def unwif(b58cstr):
    return base58.b58decode_check(b58cstr)[1:]

# extract hash160 from address
def get_pay_hash(pubkey):
    bytes = unwif(pubkey)
    return hexlify(bytes).decode('utf-8')

def get_key_from_wif(key):
    private_key = unwif(key)
    if (len(private_key) == 33):
        private_key = private_key[:-1]
    return private_key

# unchecked p2sh script
def make_payto_script(address):
    asm = "OP_HASH160 %s OP_EQUAL" % get_pay_hash(address)
    return tools.compile(asm)

# unchecked p2pubkeyhash script
def make_payto_address(address):
    asm = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % get_pay_hash(address)
    return tools.compile(asm)

# extract required keys from RS
def required_keys(redeem_script):
    keyreq = int(redeem_script[0])
    assert(keyreq & 0x50)
    return keyreq ^ 0x50

# calc input estimate based on RS
def estimate_input_size(redeem_script):
    size = 0
    num_m = required_keys(redeem_script)
    size += TX_COMPONENTS.in_prevout
    size += TX_COMPONENTS.in_scriptlen
    size += TX_COMPONENTS.in_ops
    size += TX_COMPONENTS.in_m * num_m
    size += TX_COMPONENTS.in_seq
    size += len(redeem_script)
    return size

def make_bare_tx(network, from_address, to_address, redeem_script, version=1):

    # <Tx> components
    spendables = []
    ins = []
    outs = []

    # estimate the final (signed) bytesize per input based on the redeemscript
    in_size = estimate_input_size(redeem_script)

    # initialize size and amount counters
    in_amount = Decimal(0);
    est_size = TX_COMPONENTS.version + TX_COMPONENTS.out_count + TX_COMPONENTS.in_count

    # add output size (we'll only have 1)
    est_size += TX_COMPONENTS.out_scriptlen + TX_COMPONENTS.out_scriptsize + TX_COMPONENTS.out_scriptlen

    unspent_response = sochain_get_unspents(network, from_address)

    unspents = unspent_response.get("txs", [])

    # iterate over unspents
    for tx in unspents:

        value = Decimal(tx.get("value")) * Decimal(1e8)
        in_amount += value

        script = h2b(tx.get("script_hex"))
        # for now: test if the in_script we figured we would need, actually matches the in script :D

        # reverse that tx hash
        txhex = tx.get("txid");
        prevtx = h2b_rev(txhex)

        # output index
        outnum = tx.get("output_no")

        # create "spendable"
        spdbl = Spendable(value, script, prevtx, outnum)
        spendables.append(spdbl)

        # also create this as input
        ins.append(spdbl.tx_in())

        # add the estimated size per input
        est_size += in_size

    # calc fee and out amount
    fee = Decimal(math.ceil(est_size / 1000)) * Decimal(1e8) * NETWORK_FEES.get(network)
    out_amount = in_amount - fee

    # create output
    outs.append(TxOut(out_amount, make_payto_script(to_address)))

    # create bare tx without sigs
    tx = Tx(version, ins, outs, 0, spendables)

    return tx

def sign_tx_with(tx, keys, redeem_script):
    for i in range(0, len(tx.txs_in)):
        # sigscripts start with OP_0
        asm = "OP_0"

        # get sighash
        ddata = tx.signature_hash(redeem_script, i, 0x01)

        # make sure the sighash buffer is the right size
        data_to_sign = h2b("{0:064x}".format(ddata))

        #sign with all keys
        for key in keys:

            # sign dat hash with the ecdsa lib
            s = key.sign_digest_deterministic(data_to_sign, sha256, util.sigencode_der_canonize)

            # add sigtype
            sig = b2h(s) + "01"

            # add to script
            asm += " " + sig

        # compile the script including RS
        solution = tools.compile(asm + " " + b2h(redeem_script))

        # add solution to input
        tx.txs_in[i].script = solution

    return tx

def main():

    parser = argparse.ArgumentParser(
    description="Sweeps multisig addresses")

    parser.add_argument('-t', "--transaction-version", type=int,
                        help='Transaction version, either 1 (default) or 3 (not yet supported).')

    parser.add_argument('-n', "--network", required=True,
                        help='Define network code, accepted are: (BTC, DOGE, LTC, BTCTEST, DOGETEST, LTCTEST.')

    parser.add_argument('-s', "--sweep-address", required=True, action="append",
                        help='The address you want to sweep from')

    parser.add_argument('-d', "--destination-address", required=True, action="append",
                        help='The address you want to sweep to')

    parser.add_argument('-k', "--key", action="append",
                        help='The WIF keys with which to sign the address')

    parser.add_argument('-r', '--redeem-script', action="append", required=True,
                        help='The redeem script for the swept address')

    parser.add_argument('-p', '--push', action="store_true",
                        help='Push the fully signed tx to the network')

    args = parser.parse_args()

    if not args.sweep_address:
        print("Expecting at least 1 sweep address (-s)")
        exit(1)
    else:
        from_address = args.sweep_address[0]

    if not args.destination_address:
        print("Expecting at least 1 destination address (-d)")
        exit(1)
    else:
        to_address = args.destination_address[0]

    if not args.network or not NETWORK_FEES[args.network]:
        print("Expecting a valid network (-n)!")
        print("Valid values are: BTC, DOGE, LTC, BTCTEST, DOGETEST, LTCTEST")
        exit(1)

    if not args.redeem_script:
        print("Expecting a redeem script (-r)!")
        exit(1)

    tx_version = args.transaction_version or 1

    keys = []
    if args.key:
        for key in args.key:
            keys.append(SigningKey.from_string(get_key_from_wif(key), SECP256k1, sha256))

    # Redeemscript
    rs_bin = h2b(args.redeem_script[0])

    # Calc number of required keys from redeemscript
    keyreq = required_keys(rs_bin)

    tx = make_bare_tx(args.network, from_address, to_address, rs_bin, tx_version)

    if len(tx.txs_in) < 1:
        print("Address {0} has no balance, aborting...".format(from_address))
        exit(1)

    if not len(keys):
        print("No signing keys given (-k), printing bare transaction...")
        print(tx.as_hex())
        exit(0)

    if tx.txs_out[0].coin_value < NETWORK_FEES.get(args.network):
        print("Out value lower than network fee, aborting...")
        exit(1)

    signed_tx = sign_tx_with(tx, keys, rs_bin)

    if len(keys) < keyreq:
        print("Could not sign for all required keys, printing intermediate transaction...")
        print(signed_tx.as_hex())
        exit(0)

    if args.push:
        # push the tx
        push_response = sochain_pushtx(args.network, tx)
        print("Sweep complete!\nNetwork: {0}\nTx hash: {1}".format(push_response.get("network"), push_response.get("txid")))
    else:
        print(signed_tx.as_hex())

if __name__ == '__main__':
    main()
