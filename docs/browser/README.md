---
description: Writing Sapphire dApp for browser and Metamask
---

# Browser Support

Confidential Sapphire dApps work in web browsers by wrapping the
Ethereum provider such as Metamask to enable signing and encrypting
calls and transactions.

## Sapphire ParaTime

Our `@oasisprotocol/sapphire-paratime` library makes it easy to port your dapp
to the Sapphire ParaTime by wrapping your existing EIP-1193 compatible provider
(e.g. window.ethereum). Once you wrap your provider, you can use Sapphire just
like you would use Ethereum, however to get full support for encrypted
transactions, queries and gas estimates it may be necessary to use a
framework-specific package such as with Ethers, Viem or Wagmi.

The Sapphire wrapper with automatically encrypt the eth_call, eth_estimateGas and eth_signTransaction JSON-RPC calls

### Usage

Install the library via your favorite package manager

```shell npm2yarn
npm install -D @oasisprotocol/sapphire-paratime
```

After installing this library, find your Ethereum provider and wrap it using wrapEthereumProvider.

```js
import { wrapEthereumProvider } from '@oasisprotocol/sapphire-paratime';

const provider = wrapEthereumProvider(window.ethereum);
window.ethereum = wrapEthereumProvider(window.ethereum); // If you're feeling bold.
```

:::info Example: Hardhat boilerplate

You can download a full working example from the [Sapphire ParaTime examples]
repository.

:::

:::info Example: Starter project

If your project involves building both a contract backend and a web frontend,
we recommend that you check out the official [Oasis starter] files.

[Oasis starter]: https://github.com/oasisprotocol/demo-starter

:::

## Other Browser Framework Support

Apart from the our minimal library, we have support for multiple known browser
frameworks:

- [Ethers][ethers]
- [Viem][viem]
- [Wagmi][wagmi]

[ethers]: ./ethers.md
[viem]: ./viem.md
[wagmi]: ./wagmi.md

:::info Example: Wagmi starter project

For building with Wagmi, recommend you to check out our [Wagmi starter] boilerplate.

[Wagmi starter]: https://github.com/oasisprotocol/sapphire-paratime/tree/main/examples/wagmi-v2

:::

[Sapphire ParaTime examples]: https://github.com/oasisprotocol/sapphire-paratime/tree/main/examples/hardhat-boilerplate
[pnpm]: https://pnpm.io
