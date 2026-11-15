// Dev-time probe: discover the gatekeeper circuit's input signals by testing
// candidate names against the wasm's getInputSignalSize via FNV-1a hashes
// (the same lookup circom's witness calculator performs), then run
// satisfiability tests with snarkjs to pin down the exact decision predicate.
//
// Usage: node scripts/probe-circuit.mjs
import fs from "node:fs";
import * as snarkjs from "snarkjs";

const WASM = new URL("../circuits/gatekeeper.wasm", import.meta.url).pathname;
const ZKEY = new URL("../circuits/gatekeeper_final.zkey", import.meta.url).pathname;
const VK = JSON.parse(fs.readFileSync(new URL("../circuits/vk.json", import.meta.url), "utf8"));

function fnvHash(str) {
  const MOD = 2n ** 64n;
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash = (hash * 0x100000001b3n) % MOD;
  }
  return hash;
}

async function probeNames(candidates) {
  const buf = fs.readFileSync(WASM);
  const { instance } = await WebAssembly.instantiate(buf, {
    runtime: {
      exceptionHandler: (code) => { throw new Error("wasm exception " + code); },
      printErrorMessage: () => {},
      writeBufferMessage: () => {},
      showSharedRWMemory: () => {},
    },
  });
  const ex = instance.exports;
  ex.init();
  console.log("getInputSize() =", ex.getInputSize());
  console.log("getWitnessSize() =", ex.getWitnessSize());
  for (const name of candidates) {
    for (const variant of [name, "main." + name]) {
      const h = fnvHash(variant);
      const msb = Number(h >> 32n);
      const lsb = Number(h & 0xffffffffn);
      let size = -1;
      try { size = ex.getInputSignalSize(msb, lsb); } catch { /* not found */ }
      if (size > 0) console.log(`FOUND  ${variant}  size=${size}`);
    }
  }
}

const CANDIDATES = [
  "registeredVkHash", "proofVkHash", "minimum", "publicBalance", "expiryBlock",
  "currentBlock", "recipient", "conditionRecipient", "amount", "maxTransfer",
  "decision", "taskId", "salt",
  // variants worth ruling out
  "registered_vk", "proof_vk", "public_balance", "expiry_block", "current_block",
  "condition_recipient", "max_transfer", "task_id", "balance", "min", "threshold",
  "vkHash", "registeredVk", "proofVk", "nonce", "random",
];

const REGISTERED_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b1";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const OTHER_RECIPIENT = "0xDe42000000000000000000000000000000009f02";

function baseInput(overrides = {}) {
  return {
    registeredVkHash: REGISTERED_VK,
    proofVkHash: REGISTERED_VK,
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: "8430000",
    currentBlock: "8420000",
    recipient: RECIPIENT,
    conditionRecipient: RECIPIENT,
    amount: "500",
    maxTransfer: "1000",
    decision: "1",
    taskId: "123456789",
    salt: "987654321",
    ...overrides,
  };
}

async function tryProve(label, input, expectOk) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    console.log(`${label}: PROVED, verify=${ok} (expected prove=${expectOk})`);
    return { proof, publicSignals };
  } catch (e) {
    console.log(`${label}: PROVE FAILED (${String(e.message || e).slice(0, 80)}) (expected prove=${expectOk})`);
    return null;
  }
}

await probeNames(CANDIDATES);

console.log("\n--- satisfiability matrix ---");
const valid = await tryProve("A valid, decision=1           ", baseInput(), true);
if (valid) {
  console.log("publicSignals (" + valid.publicSignals.length + "):");
  const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const named = {
    registeredVkHash: BigInt(REGISTERED_VK) % P,
    proofVkHash: BigInt(REGISTERED_VK) % P,
    minimum: 1000n, publicBalance: 1460n, expiryBlock: 8430000n, currentBlock: 8420000n,
    recipient: BigInt(RECIPIENT), conditionRecipient: BigInt(RECIPIENT),
    amount: 500n, maxTransfer: 1000n, decision: 1n, taskId: 123456789n, salt: 987654321n,
  };
  valid.publicSignals.forEach((s, i) => {
    const match = Object.entries(named).find(([, v]) => v === BigInt(s));
    console.log(`  [${i}] ${s}  ${match ? "== " + match[0] : "(no input match — output?)"}`);
  });
}
await tryProve("B valid, decision=0           ", baseInput({ decision: "0" }), false);
await tryProve("C recipient trap, decision=1  ", baseInput({ conditionRecipient: OTHER_RECIPIENT }), false);
await tryProve("D recipient trap, decision=0  ", baseInput({ conditionRecipient: OTHER_RECIPIENT, decision: "0" }), true);
await tryProve("E vk mismatch, decision=1     ", baseInput({ proofVkHash: OTHER_VK }), false);
await tryProve("E vk mismatch, decision=0     ", baseInput({ proofVkHash: OTHER_VK, decision: "0" }), true);
await tryProve("F expired blk, decision=0     ", baseInput({ currentBlock: "8430001", decision: "0" }), true);
await tryProve("F expired blk, decision=1     ", baseInput({ currentBlock: "8430001" }), false);
await tryProve("G amount>max, decision=0      ", baseInput({ amount: "1001", decision: "0" }), true);
await tryProve("H balance<min, decision=0     ", baseInput({ publicBalance: "999", decision: "0" }), true);

console.log("\n--- boundary semantics (decision=1 must prove iff condition is inclusive) ---");
await tryProve("I amount == maxTransfer       ", baseInput({ amount: "1000" }), true);
await tryProve("J balance == minimum          ", baseInput({ publicBalance: "1000" }), true);
await tryProve("K currentBlock == expiryBlock ", baseInput({ currentBlock: "8430000" }), true);
await tryProve("L salt=0 valid                ", baseInput({ salt: "0" }), true);
process.exit(0);
