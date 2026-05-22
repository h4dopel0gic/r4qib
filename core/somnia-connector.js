// ============================================================
// R4qib — Somnia Connector v1.1
// Chain-agnostic EVM connector. Chain config drives everything.
// API: Etherscan-compatible Blockscout (?module=contract&action=getsourcecode)
// ============================================================

import { ethers } from 'ethers';
import https from 'https';

export const CHAINS = {
  'somnia-testnet': {
    name: 'Somnia Shannon Testnet',
    rpcUrl: 'https://api.infra.testnet.somnia.network/',
    chainId: 50312,
    symbol: 'STT',
    explorerUrl: 'https://shannon-explorer.somnia.network',
    explorerApiUrl: 'https://somnia.w3us.site/api',
  },
  'somnia-mainnet': {
    name: 'Somnia Mainnet',
    rpcUrl: 'https://api.infra.mainnet.somnia.network/',
    chainId: 5031,
    symbol: 'SOMI',
    explorerUrl: 'https://explorer.somnia.network',
    explorerApiUrl: 'https://explorer.somnia.network/api',
  },
  'ethereum-mainnet': {
    name: 'Ethereum Mainnet',
    rpcUrl: 'https://eth.public-rpc.com',
    chainId: 1,
    symbol: 'ETH',
    explorerUrl: 'https://etherscan.io',
    explorerApiUrl: 'https://api.etherscan.io/api',
  },
  'base-mainnet': {
    name: 'Base Mainnet',
    rpcUrl: 'https://mainnet.base.org',
    chainId: 8453,
    symbol: 'ETH',
    explorerUrl: 'https://basescan.org',
    explorerApiUrl: 'https://api.basescan.org/api',
  },
};

export function getProvider(chainKey = 'somnia-testnet') {
  const chain = CHAINS[chainKey];
  if (!chain) throw new Error(`Unknown chain: ${chainKey}`);
  return new ethers.JsonRpcProvider(chain.rpcUrl);
}

export async function testConnection(chainKey = 'somnia-testnet') {
  const chain = CHAINS[chainKey];
  const provider = getProvider(chainKey);
  console.log(`\n🔌 Connecting to ${chain.name}...`);
  const [blockNumber, network] = await Promise.all([
    provider.getBlockNumber(),
    provider.getNetwork()
  ]);
  console.log(`✅ Connected`);
  console.log(`   Chain ID : ${network.chainId}`);
  console.log(`   Block    : ${blockNumber}`);
  console.log(`   RPC      : ${chain.rpcUrl}`);
  return { chainId: network.chainId.toString(), blockNumber };
}

export async function getContractBytecode(address, chainKey = 'somnia-testnet') {
  const provider = getProvider(chainKey);
  const code = await provider.getCode(address);
  if (code === '0x') {
    return { success: false, error: 'No contract at this address (EOA or empty)' };
  }
  return { success: true, address, bytecode: code, size: (code.length - 2) / 2 };
}

export async function getVerifiedSource(address, chainKey = 'somnia-testnet') {
  const chain = CHAINS[chainKey];
  const url = `${chain.explorerApiUrl}?module=contract&action=getsourcecode&address=${address}`;
  return new Promise((resolve) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const contract = parsed?.result?.[0];
          if (parsed.status === '1' && contract?.SourceCode && contract.SourceCode !== '') {
            resolve({
              success: true, verified: true, address,
              name: contract.ContractName || 'Unknown',
              sourceCode: contract.SourceCode,
              abi: contract.ABI || '[]',
              compilerVersion: contract.CompilerVersion,
              optimizationUsed: contract.OptimizationUsed,
            });
          } else {
            resolve({ success: true, verified: false, address, message: 'Contract exists but source not verified' });
          }
        } catch (e) {
          resolve({ success: false, error: `Explorer API parse error: ${e.message}` });
        }
      });
    }).on('error', (e) => {
      resolve({ success: false, error: `Explorer API request failed: ${e.message}` });
    });
  });
}

export async function fetchContractForAnalysis(address, chainKey = 'somnia-testnet') {
  console.log(`\n👁️  R4qib fetching contract: ${address}`);
  console.log(`   Chain: ${CHAINS[chainKey].name}`);
  const bytecodeResult = await getContractBytecode(address, chainKey);
  if (!bytecodeResult.success) return { success: false, error: bytecodeResult.error };
  console.log(`   ✅ Contract confirmed (${bytecodeResult.size} bytes)`);
  const sourceResult = await getVerifiedSource(address, chainKey);
  if (sourceResult.verified) {
    console.log(`   ✅ Source verified — ${sourceResult.name}`);
    return {
      success: true, address, chain: chainKey,
      name: sourceResult.name, hasSource: true,
      sourceCode: sourceResult.sourceCode, abi: sourceResult.abi,
      compilerVersion: sourceResult.compilerVersion,
      bytecodeSize: bytecodeResult.size, readyForAnalysis: true,
    };
  }
  console.log(`   ⚠️  Source not verified — bytecode only`);
  return {
    success: true, address, chain: chainKey, hasSource: false,
    bytecode: bytecodeResult.bytecode, bytecodeSize: bytecodeResult.size,
    readyForAnalysis: true,
    analysisNote: 'Unverified contract — analysis based on bytecode only. Accuracy reduced.',
  };
}
