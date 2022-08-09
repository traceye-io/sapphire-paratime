import { arrayify, hexlify } from '@ethersproject/bytes';
import * as cbor from 'cborg';
import { Wallet, ethers, BigNumber } from 'ethers';

import {
  PrepareSignedCallOverrides,
  SignedCall,
  SignedCallDataPack,
  makeSignableCall,
  prepareSignedCall,
  signedCallEIP712Params,
} from '@oasislabs/sapphire-paratime/signed_calls';

const CHAIN_ID = 0x5afe;

describe('signed calls', () => {
  // 0x11e244400Cf165ade687077984F09c3A037b868F
  const from = new Wallet(
    '0x8160d68c4bf9425b1d3a14dc6d59a99d7d130428203042a8d419e68d626bd9f2',
  );
  const to = '0xb5ed90452AAC09f294a0BE877CBf2Dc4D55e096f';

  const overrides: PrepareSignedCallOverrides = {
    leash: {
      nonce: 999,
      block: {
        hash: '0xc92b675c7013e33aa88feaae520eb0ede155e7cacb3c4587e0923cba9953f8bb',
        number: 42,
      },
      blockRange: 3,
    },
    chainId: CHAIN_ID,
  };

  it('signs', async () => {
    const call = {
      from: from.address,
      to,
      gasLimit: 10,
      gasPrice: 123,
      value: 42,
      data: [1, 2, 3, 4],
    };

    const signedCall = await prepareSignedCall(call, from, overrides);
    expect(signedCall).toMatchObject({
      ...call,
      data: signedCall.data, // don't check this field (yet)
    });

    const dataPack = verify(signedCall);
    expect(dataPack.data?.body).toEqual(new Uint8Array(call.data));
    expect(dataPack.leash.nonce).toEqual(overrides.leash?.nonce);
    expect(dataPack.leash.block_number).toEqual(overrides.leash!.block!.number);
    expect(hexlify(dataPack.leash.block_hash)).toEqual(
      overrides.leash!.block!.hash!,
    );
    expect(dataPack.leash.block_range).toEqual(overrides.leash?.blockRange);
  });

  it('partial', async () => {
    const call = {
      from: from.address,
    };

    const signedCall = await prepareSignedCall(call, from, overrides);
    expect(signedCall).toMatchObject({
      ...call,
      data: signedCall.data, // don't check this field (yet)
    });

    verify(signedCall);
  });

  it('defaults', async () => {
    const call = {
      from: from.address,
    };

    const signable = makeSignableCall(call, {
      nonce: 2,
      block_number: 1,
      block_range: 4,
      block_hash: new Uint8Array(),
    });

    expect(signable).toEqual({
      from: from.address,
      to: '0x0000000000000000000000000000000000000000',
      gasLimit: 0,
      gasPrice: BigNumber.from(0),
      value: BigNumber.from(0),
      data: '0x',
      leash: {
        nonce: 2,
        blockNumber: 1,
        blockRange: 4,
        blockHash: new Uint8Array(),
      },
    });
  });
});

function verify(call: SignedCall): SignedCallDataPack {
  const { domain, types } = signedCallEIP712Params(CHAIN_ID);
  const dataPack: SignedCallDataPack = cbor.decode(arrayify(call.data));
  const recoveredSender = ethers.utils.verifyTypedData(
    domain,
    types,
    makeSignableCall(
      { ...call, data: dataPack.data ? dataPack.data.body : undefined },
      dataPack.leash,
    ),
    dataPack.signature,
  );
  if (call.from !== recoveredSender) {
    throw new Error('signed call signature verification failed');
  }
  return dataPack;
}
