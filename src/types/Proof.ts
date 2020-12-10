import { ProofPurpose } from "./ProofPurpose";

export interface Proof {
  type: string;
  nonce?: string;
  proofValue?: string;
  verificationMethod: string;
  proofPurpose: ProofPurpose;
  created: string;
}
