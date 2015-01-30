import io
import json
import six
import base58
import math
import requests
import argparse
import random

from decimal import *
from ecdsa import SigningKey, SECP256k1, util
from hashlib import sha256
from binascii import hexlify, unhexlify
from collections import namedtuple

from pycoin.serialize import b2h, h2b, h2b_rev, b2h_rev
from pycoin.tx.script import tools
from pycoin.tx import Tx, Spendable, TxOut

# set decimal precision for Decimal to 8 positions
getcontext().prec = 8

# size estimation constants
TxComponents = namedtuple("TxComponents",
                           ("version", "in_count", "out_count", "locktime", "in_prevout",
                            "in_scriptlen", "in_ops", "in_m", "in_seq", "out_value", "out_scriptlen", "out_scriptsize"))
TX_COMPONENTS = TxComponents(4,3,3,4,36,4,3,73,4,8,1,35)

# fee estimation constants
NETWORK_FEES = {"BTC": Decimal(0.0001), "DOGE": Decimal(1), "LTC": Decimal(0.001), "BTCTEST": Decimal(0.0001), "DOGETEST": Decimal(1), "LTCTEST": Decimal(0.001)}

# static tx version for now
TX_VERSION = 1

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

def get_blockio_signatures(network, from_address, redeem_script, tx):
    inputs = [];
    for i in range(0, len(tx.txs_in)):
        inputs.append({
            "input_no": i,
            "data_to_sign": get_sighash_hex(tx, i, redeem_script),
            "signed_data": "",
            "address": from_address
        })
    data = {"network": network, "reference_id": get_random_hex(), "inputs": inputs }
    url = "https://block.io/api/v2/get_dtrust_signature"

    session = requests.session()
    response = session.post(url, data="signature_data={0}".format(json.dumps(data)))
    response = response.json().get("data", {})
    session.close()

    return response

def get_random_hex():
    rhex = "{0:032x}".format(random.getrandbits(32*8))
    return rhex

def unwif(b58cstr):
    bytes = base58.b58decode_check(b58cstr)
    return (bytes[0], bytes[1:])

# extract hash160 from address
def get_pay_hash(pubkey):
    bytes = unwif(pubkey)[1]
    return hexlify(bytes).decode("utf-8")

def get_key_from_wif(key):
    private_key = unwif(key)[1]
    if (len(private_key) == 33):
        private_key = private_key[:-1]
    return private_key

def is_p2sh(address):
    return hexlify(unwif(address)[0]) in ['05', '16', 'c4']

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
    keyreq = read_int_from_bin(redeem_script[0])
    assert(keyreq & 0x50)
    return keyreq ^ 0x50

def read_int_from_bin(binstr):
    return int(b2h(binstr), base=16) if six.PY2 else int(binstr);

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

    # add output size (we"ll only have 1)
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
        as_input = spdbl.tx_in()
        as_input.sigs = []
        ins.append(as_input)

        # add the estimated size per input
        est_size += in_size

    # calc fee and out amount
    fee = Decimal(math.ceil(est_size / 1000.0)) * Decimal(1e8) * NETWORK_FEES.get(network)
    out_amount = in_amount - fee

    if (is_p2sh(to_address)):
        outscript = make_payto_script(to_address)
    else:
        outscript = make_payto_address(to_address)

    # create output
    outs.append(TxOut(out_amount, outscript))

    # create bare tx without sigs
    tx = Tx(version, ins, outs, 0, spendables)

    return tx

def sign_tx_with(tx, keys, redeem_script):
    for i in range(0, len(tx.txs_in)):
        # sigscripts start with OP_0
        asm = "OP_0"

        data_to_sign = h2b(get_sighash_hex(tx, i, redeem_script))
        #sign with all keys
        for key in keys:

            # sign dat hash with the ecdsa lib
            s = key.sign_digest_deterministic(data_to_sign, sha256, util.sigencode_der_canonize)

            # add sigtype
            sig = b2h(s) + "01"

            tx.txs_in[i].sigs.append(sig)

    return tx

def build_tx(tx, redeem_script):
    for i in range(0, len(tx.txs_in)):
        asm = "OP_0 {sigs} {redeem_script}".format(sigs=" ".join(tx.txs_in[i].sigs), redeem_script=b2h(redeem_script))
        solution = tools.compile(asm)
        tx.txs_in[i].script = solution
    return tx

def add_blockio_signatures(network, from_address, tx, redeem_script):
    response = get_blockio_signatures(network, from_address, redeem_script, tx)
    signed_inputs = response.get("inputs", [])
    for i in range(0, len(signed_inputs)):
        idx = signed_inputs[i].get("input_no")
        sig = signed_inputs[i].get("signed_data")
        tx.txs_in[idx].sigs.insert(0, sig + "01")
    return tx

def get_sighash_hex(tx, i, redeem_script):
    # get sighash
    ddata = tx.signature_hash(redeem_script, i, 0x01)

    # make sure the sighash buffer is the right size
    return "{0:064x}".format(ddata)

def main():

    parser = argparse.ArgumentParser(
    description="Sweeps multisig addresses")

    parser.add_argument("-n", "--network", required=True,
                        help="Define network code, accepted are: (BTC, DOGE, LTC, BTCTEST, DOGETEST, LTCTEST.")
    parser.add_argument("-s", "--sweep-address", required=True, action="append",
                        help="The address you want to sweep from")
    parser.add_argument("-d", "--destination-address", required=True, action="append",
                        help="The address you want to sweep to")
    parser.add_argument("-k", "--key", action="append",
                        help="The WIF keys with which to sign the address")
    parser.add_argument("-r", "--redeem-script", action="append", required=True,
                        help="The redeem script for the swept address, enclose in \"\"")
    parser.add_argument("-p", "--push", action="store_true",
                        help="Push the fully signed tx to the network")
    parser.add_argument("-b", "--blockio-sign", action="store_true",
                        help="Ask block.io to sign this transaction")

    args = parser.parse_args()

    if not args.sweep_address:
        six.print_("Expecting at least 1 sweep address (-s)")
        exit(1)
    else:
        from_address = args.sweep_address[0]

    if not args.destination_address:
        six.print_("Expecting at least 1 destination address (-d)")
        exit(1)
    else:
        to_address = args.destination_address[0]

    if not args.network or not args.network in NETWORK_FEES:
        six.print_("Expecting a valid network (-n)!")
        six.print_("Valid values are: BTC, DOGE, LTC, BTCTEST, DOGETEST, LTCTEST")
        exit(1)

    if not args.redeem_script:
        six.print_("Expecting a redeem script (-r)!")
        exit(1)

    keys = []
    if args.key:
        for key in args.key:
            keys.append(SigningKey.from_string(get_key_from_wif(key), SECP256k1, sha256))

    # Redeemscript
    rs_bin = tools.compile(args.redeem_script[0])

    # Calc number of required keys from redeemscript
    keyreq = required_keys(rs_bin)

    tx = make_bare_tx(args.network, from_address, to_address, rs_bin, TX_VERSION)

    if len(tx.txs_in) < 1:
        six.print_("Address {0} has no balance, aborting...".format(from_address))
        exit(1)

    if not len(keys):
        six.print_("No signing keys given (-k), printing bare transaction...")
        six.print_(tx.as_hex())
        exit(0)

    if tx.txs_out[0].coin_value < NETWORK_FEES.get(args.network):
        six.print_("Out value lower than network fee, aborting...")
        exit(1)

    signed_tx = sign_tx_with(tx, keys, rs_bin)

    if len(keys) < keyreq and args.blockio_sign:
            signed_tx = add_blockio_signatures(args.network, from_address, signed_tx, rs_bin)

    built_tx = build_tx(signed_tx, rs_bin)

    if len(signed_tx.txs_in[0].sigs) < keyreq:
        six.print_("Could not sign for all required keys, printing intermediate transaction...")
        six.print_(built_tx.as_hex())
        exit(0)

    if args.push:
        # push the tx
        push_response = sochain_pushtx(args.network, built_tx)
        txid = push_response.get("txid")
        if not txid:
            six.print_("Pushing transaction failed, printing transaction...\n{0}".format(built_tx.as_hex()))
        else:
            six.print_("Sweep complete!\nNetwork: {0}\nTx hash: {1}".format(push_response.get("network"), txid))
    else:
        six.print_(built_tx.as_hex())

if __name__ == "__main__":
    main()
