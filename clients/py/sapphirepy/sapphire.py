from typing import Any, Callable, cast, TypedDict, Optional
from binascii import unhexlify, hexlify

import cbor2
from web3 import Web3
from web3.types import RPCEndpoint, RPCResponse, TxParams, Middleware
from eth_typing import HexStr
from eth_account import Account
from typing import (
    Any,
    Callable,
    Collection,
    Union,
)
from eth_account.signers.local import (
    LocalAccount,
)

from .envelope import TransactionCipher

# Should transactions which deploy contracts be encrypted?
ENCRYPT_DEPLOYS = False

# Number of epochs to keep public keys for
EPOCH_LIMIT = 5
#Default gas price
DEFAULT_GAS_PRICE = 100_000_000_000
#Default gas limit
DEFAULT_GAS_LIMIT = 30_000_000
#Default block range
DEFAULT_BLOCK_RANGE = 15

class CalldataPublicKey(TypedDict):
    epoch: int
    checksum: HexStr
    signature: HexStr
    key: HexStr


class CalldataPublicKeyManager:
    _keys: list[CalldataPublicKey]

    def __init__(self):
        self._keys = []

    def _trim_and_sort(self, newest_epoch: int):
        self._keys = sorted([v for v in self._keys
                             if v['epoch'] >= newest_epoch - EPOCH_LIMIT],
                            key=lambda o: o['epoch'])[-EPOCH_LIMIT:]

    @property
    def newest(self):
        if self._keys:
            return self._keys[-1]
        return None

    def add(self, pk: CalldataPublicKey):
        if self._keys:
            if self.newest['epoch'] < pk['epoch']:
                self._keys.append(pk)
            self._trim_and_sort(pk['epoch'])
        else:
            self._keys.append(pk)


def _should_intercept(method: RPCEndpoint, params: tuple[TxParams]):
    if not ENCRYPT_DEPLOYS:
        if method in ('eth_sendTransaction', 'eth_estimateGas'):
            # When 'to' flag is missing, we assume it's a deployment
            if not params[0].get('to', None):
                return False
    return method in ('eth_estimateGas', 'eth_sendTransaction', 'eth_call')


def _encrypt_tx_params(pk: CalldataPublicKey,
                       params: tuple[TxParams],
                       web3: Web3,
                       account: LocalAccount) -> TransactionCipher:
    c = TransactionCipher(peer_pubkey=pk['key'], peer_epoch=pk['epoch'])
    data = params[0]['data']
    if isinstance(data, bytes):
        data_bytes = data
    elif isinstance(data, str):
        if len(data) < 2 or data[:2] != '0x':
            raise ValueError('Data is not hex encoded!', data)
        data_bytes = unhexlify(data[2:])
    else:
        raise TypeError("Invalid 'data' type", type(data))
    encrypted_data = c.encrypt(data_bytes)

    # if False:
    if params[0]['from'] and params[0]['from'] == account.address:
        domain_data = {
            "name": "oasis-runtime-sdk/evm: signed query",
            "version": "1.0.0",
            "chainId": web3.eth.chain_id,
            # "verifyingContract": "",
            # "salt": "",
        }
        msg_types = {
            "Call": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "gasLimit", "type": "uint64"},
                {"name": "gasPrice", "type": "uint256"},
                {"name": "value", "type": "uint256"},
                {"name": "data", "type": "bytes"},
                {"name": "leash", "type": "Leash"},
            ],
            "Leash": [
                {"name": "nonce", "type": "uint64"},
                {"name": "blockNumber", "type": "uint64"},
                {"name": "blockHash", "type": "bytes32"},
                {"name": "blockRange", "type": "uint64"},
            ],
        }
        msg_data = {
            "from": params[0].get('from'),
            "to": params[0].get('to', '0x'),
            "value": params[0].get('value', 0),
            "gasLimit": params[0].get('gas', DEFAULT_GAS_LIMIT),
            "gasPrice": params[0].get('gasPrice', DEFAULT_GAS_PRICE),
            "data": params[0].get('data'),
            "leash":
                {
                    "nonce": web3.eth.get_transaction_count(params[0].get('from')),
                    "blockNumber": web3.eth.block_number-1,
                    "blockHash": web3.eth.get_block(web3.eth.block_number)['hash'],
                    "blockRange": DEFAULT_BLOCK_RANGE,
                }
        }

        # sign the message with the private key:
        signed_msg = Account.sign_typed_data(account.key, domain_data, msg_types, msg_data)
        leash = {
            'Nonce': web3.eth.get_transaction_count(params[0]['from']),
            'BlockNumber': web3.eth.block_number-1,
            'BlockHash': web3.eth.get_block(web3.eth.block_number)['hash'],
            'BlockRange': DEFAULT_BLOCK_RANGE,
        }
        data_pack = {
            'data': params[0]['data'],
            # 'data': encrypted_data,
            'leash': leash,
            'signature': signed_msg['signature'],
        }
        params[0]['data'] = cbor2.dumps(data_pack, canonical=True)
        params[0]['data'] = '0x' + params[0]['data'].hex()
        return c

    params[0]['data'] = HexStr('0x' + hexlify(encrypted_data).decode('ascii'))
    return c

def construct_sapphire_middleware(
        account: LocalAccount = None
) -> Middleware:
    """
    Construct a Sapphire middleware for Web3.py.
    :param account: Used to encrypt signed queries.
    :return: A Sapphire middleware function.
    """
    def sapphire_middleware(
            make_request: Callable[[RPCEndpoint, Any], Any], w3: "Web3"
    ) -> Callable[[RPCEndpoint, Any], RPCResponse]:
        """
        Transparently encrypt the calldata for:

         - eth_estimateGas
         - eth_sendTransaction
         - eth_call

        The calldata public key, which used to derive a shared secret with an
        ephemeral key, is retrieved upon the first request. This key is rotated by
        Sapphire every epoch, and only transactions encrypted with keys from the
        last 5 epochs are considered valid.

        Deployment transactions will not be encrypted, unless the global
        ENCRYPT_DEPLOYS flag is set. Encrypting deployments will prevent contracts
        from being verified.

        Pre-signed transactions can't be encrypted if submitted via this instance.
        """
        manager = CalldataPublicKeyManager()

        def middleware(method: RPCEndpoint, params: Any) -> RPCResponse:
            if _should_intercept(method, params):
                do_fetch = True
                pk = manager.newest
                while do_fetch:
                    if not pk:
                        # If no calldata public key exists, fetch one
                        cdpk = cast(RPCResponse, make_request(RPCEndpoint('oasis_callDataPublicKey'), []))
                        pk = cast(Optional[CalldataPublicKey], cdpk.get('result', None))
                        if pk:
                            manager.add(pk)
                    if not pk:
                        raise RuntimeError('Could not retrieve callDataPublicKey!')
                    do_fetch = False

                    c = _encrypt_tx_params(pk, params, w3,  account)

                    # We may encounter three errors here:
                    #  'core: invalid call format: epoch too far in the past'
                    #  'core: invalid call format: Tag verification failed'
                    #  'core: invalid call format: epoch in the future'
                    # We can only do something meaningful with the first!
                    result = cast(RPCResponse, make_request(method, params))
                    if result.get('error', None) is not None:
                        error = result['error']
                        if not isinstance(error, str) and error['code'] == -32000:
                            if error['message'] == 'core: invalid call format: epoch too far in the past':
                                # force the re-fetch, and encrypt with new key
                                do_fetch = True
                                pk = None
                                continue

                # Only eth_call is decrypted
                if method == 'eth_call' and result.get('result', '0x') != '0x':
                    decrypted = c.decrypt(unhexlify(result['result'][2:]))
                    result['result'] = HexStr('0x' + hexlify(decrypted).decode('ascii'))

                return result
            return make_request(method, params)

        return middleware

    return sapphire_middleware

def wrap(w3: Web3, account: LocalAccount = None):
    """
    Adds the Sapphire transaction encryption middleware to a Web3.py provider.

    Note: the provider must be wrapped *after* any signing middleware has been
          added, otherwise pre-signed transactions will not be encrypted.
    """
    if 'sapphire' not in w3.middleware_onion:
        w3.middleware_onion.add(construct_sapphire_middleware(account), "sapphire")
    return w3
