declare module "snarkjs" {
  export interface SnarkjsProof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  }
  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmFile: string,
      zkeyFile: string
    ): Promise<{ proof: SnarkjsProof; publicSignals: string[] }>;
    verify(
      verificationKey: unknown,
      publicSignals: string[],
      proof: SnarkjsProof
    ): Promise<boolean>;
  };
}
