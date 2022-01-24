import {
  expExampleBls12381KeyPair,
  expVCDocumentForRangeProof,
  expRevealDocumentForRangeProof,
  customLoader
} from "./__fixtures__";

import {
  BbsTermwiseSignatureProof2021,
  BbsTermwiseSignature2021,
  Bls12381G2KeyPair
} from "../src/index";

import { signDeriveVerifyMulti } from "./utils";

const expKey1 = new Bls12381G2KeyPair(expExampleBls12381KeyPair);

describe("BbsTermwise2021 and BbsTermwiseSignature2021", () => {
  it("should derive and verify a proof including range proofs", async () => {
    const vc = { ...expVCDocumentForRangeProof };
    const hiddenUris: string[] = [];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: expRevealDocumentForRangeProof, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });
});
