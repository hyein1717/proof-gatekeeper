// Follow-up probes: (M) does the circuit embed the true registered VK hash,
// or only check proofVkHash == registeredVkHash? (P) is publicSignals[0]
// bound to the private salt?
import fs from "node:fs";
import * as snarkjs from "snarkjs";

const WASM = new URL("../circuits/gatekeeper.wasm", import.meta.url).pathname;
const ZKEY = new URL("../circuits/gatekeeper_final.zkey", import.meta.url).pathname;
const VK = JSON.parse(fs.readFileSync(new URL("../circuits/vk.json", import.meta.url), "utf8"));

const REGISTERED_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b1";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";

const base = (o = {}) => ({
  registeredVkHash: REGISTERED_VK, proofVkHash: REGISTERED_VK,
  minimum: "1000", publicBalance: "1460", expiryBlock: "8430000", currentBlock: "8420000",
  recipient: RECIPIENT, conditionRecipient: RECIPIENT,
  amount: "500", maxTransfer: "1000", decision: "1", taskId: "123456789", salt: "987654321",
  ...o,
});

async function tryProve(label, input) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    console.log(`${label}: PROVED verify=${ok}`);
    return publicSignals;
  } catch {
    console.log(`${label}: PROVE FAILED`);
    return null;
  }
}

await tryProve("M both vk = OTHER (equal, wrong), decision=1", base({ registeredVkHash: OTHER_VK, proofVkHash: OTHER_VK }));
await tryProve("M both vk = OTHER (equal, wrong), decision=0", base({ registeredVkHash: OTHER_VK, proofVkHash: OTHER_VK, decision: "0" }));
await tryProve("N registered=OTHER, proof=REAL, decision=0    ", base({ registeredVkHash: OTHER_VK, decision: "0" }));

const s1 = await tryProve("P valid salt=111", base({ salt: "111" }));
const s2 = await tryProve("P valid salt=222", base({ salt: "222" }));
if (s1 && s2) {
  console.log("output[0] changes with salt:", s1[0] !== s2[0]);
  console.log("other public signals identical:", s1.slice(1).join() === s2.slice(1).join());
}
const t2 = await tryProve("P valid taskId=999999999 (salt=111)", base({ salt: "111", taskId: "999999999" }));
if (s1 && t2) console.log("output[0] changes with taskId:", s1[0] !== t2[0]);
process.exit(0);
