// SPDX-License-Identifier: Apache-2.0

import { expect } from 'chai';
import { config, ethers } from 'hardhat';
import { Signer } from 'ethers';
import { SiweMessage } from 'siwe';
import '@nomicfoundation/hardhat-chai-matchers';

import { NETWORKS } from '@oasisprotocol/sapphire-paratime';
import { HardhatNetworkHDAccountsConfig } from 'hardhat/types';

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe('Auth', function () {
  async function deploy(domain: string) {
    const SiweAuthTests_factory = await ethers.getContractFactory(
      'SiweAuthTests',
    );
    const siweAuthTests = await SiweAuthTests_factory.deploy(domain);
    await siweAuthTests.waitForDeployment();
    return siweAuthTests;
  }

  async function siweMsg(
    domain: string,
    signerIdx: number,
    expiration?: Date,
  ): Promise<string> {
    return new SiweMessage({
      domain,
      address: await (await ethers.provider.getSigner(signerIdx)).getAddress(),
      statement: `I accept the ExampleOrg Terms of Service: http://${domain}/tos`,
      uri: `http://${domain}:5173`,
      version: '1',
      chainId: Number((await ethers.provider.getNetwork()).chainId),
      expirationTime: expiration ? expiration.toISOString() : undefined,
    }).toMessage();
  }

  // Signs the given message as ERC-191 "personal_sign" message.
  async function erc191sign(msg: string, account: Signer) {
    return ethers.Signature.from(await account.signMessage(msg));
  }

  it('Should login', async function () {
    // Skip this test on non-sapphire chains.
    // It requires on-chain encryption and/or signing.
    if (
      Number((await ethers.provider.getNetwork()).chainId) !=
      NETWORKS.localnet.chainId
    ) {
      this.skip();
    }

    const siweAuthTests = await deploy('localhost');

    // Correct login.
    const accounts = config.networks.hardhat
      .accounts as HardhatNetworkHDAccountsConfig;
    const account = ethers.HDNodeWallet.fromMnemonic(
      ethers.Mnemonic.fromPhrase(accounts.mnemonic),
      accounts.path + '/0',
    );
    const siweStr = await siweMsg('localhost', 0);
    await expect(
      await siweAuthTests.testLogin(
        siweStr,
        await erc191sign(siweStr, account),
      ),
    ).lengthOf.to.be.greaterThan(2); // Test if not 0x or empty.

    // Wrong domain.
    const siweStrWrongDomain = await siweMsg('localhost2', 0);
    await expect(
      siweAuthTests.testLogin(
        siweStrWrongDomain,
        await erc191sign(siweStrWrongDomain, account),
      ),
    ).to.be.reverted;

    // Mismatch signature based on the SIWE message.
    const siweStrWrongSig = await siweMsg('localhost', 1);
    await expect(
      siweAuthTests.testLogin(
        siweStrWrongSig,
        await erc191sign(siweStrWrongSig, account),
      ),
    ).to.be.reverted;

    // Expired login.
    let now = new Date();
    const siweStrExpired = await siweMsg(
      'localhost',
      0,
      new Date(Date.now() - 10_000), // Expired 10 seconds ago.
    );
    await expect(
      siweAuthTests.testLogin(
        siweStrExpired,
        await erc191sign(siweStrExpired, account),
      ),
    ).to.be.reverted;
  });

  for (let i = 0; i<10; i++) {
    it('Should call authenticated method' + i, async function () {
      // Skip this test on non-sapphire chains.
      // It require on-chain encryption and/or signing.
      if (
        Number((await ethers.provider.getNetwork()).chainId) !=
        NETWORKS.localnet.chainId
      ) {
        this.skip();
      }

      const siweAuthTests = await deploy('localhost');

      // Author should read a very secret message.
      const accounts = config.networks.hardhat
        .accounts as HardhatNetworkHDAccountsConfig;
      const account = ethers.HDNodeWallet.fromMnemonic(
        ethers.Mnemonic.fromPhrase(accounts.mnemonic),
        accounts.path + '/0',
      );
      const siweStr = await siweMsg('localhost', 0);
      const bearer = await siweAuthTests.testLogin(
        siweStr,
        await erc191sign(siweStr, account),
      );
      expect(await siweAuthTests.testVerySecretMessage(bearer)).to.be.equal(
        'Very secret message',
      );

      // Anyone else trying to read the very secret message should fail.
      const acc2 = ethers.HDNodeWallet.fromMnemonic(
        ethers.Mnemonic.fromPhrase(accounts.mnemonic),
        accounts.path + '/1',
      );
      const siweStr2 = await siweMsg('localhost', 1);
      const bearer2 = await siweAuthTests.testLogin(
        siweStr2,
        await erc191sign(siweStr2, acc2),
      );
      await expect(siweAuthTests.testVerySecretMessage(bearer2)).to.be.reverted;

      // Same user, hijacked bearer from another contract/domain.
      const siweAuthTests2 = await deploy('localhost2');
      const siweStr3 = await siweMsg('localhost2', 0);
      const bearer3 = await siweAuthTests2.testLogin(
        siweStr3,
        await erc191sign(siweStr3, account),
      );
      await expect(siweAuthTests.testVerySecretMessage(bearer3)).to.be.reverted;

      // Expired bearer.
      const expiration = new Date(Date.now() + 500);
      const siweStr4 = await siweMsg('localhost', 0, expiration); // Expire after 0.5 seconds.
      const bearer4 = await siweAuthTests.testLogin(
        siweStr4,
        await erc191sign(siweStr4, account),
      );
      await delay(expiration.getTime() - Date.now());
      await siweAuthTests.doNothing(); // +1 block
      await siweAuthTests.doNothing(); // +1 block
      await expect(siweAuthTests.testVerySecretMessage(bearer4)).to.be.reverted;

      // Revoke bearer.
      const bearer5 = await siweAuthTests.testLogin(
        siweStr,
        await erc191sign(siweStr, account),
      );
      await siweAuthTests.testRevokeBearer(ethers.keccak256(bearer5));
      await expect(siweAuthTests.testVerySecretMessage(bearer5)).to.be.reverted;
    });
  }
});
