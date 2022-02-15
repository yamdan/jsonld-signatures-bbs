import {
  expExampleBls12381KeyPair,
  expExampleBls12381KeyPair2,
  expVCDocumentForRangeProof,
  expVCDocumentForRangeProof2,
  expRevealDocumentWithoutRangeProof,
  expRevealDocumentForRangeProof,
  expRevealDocumentForRangeProof2,
  customLoader,
  expVCDocumentForRangeProofInvalid
} from "./__fixtures__";

import {
  BbsTermwiseSignatureProof2021,
  BbsTermwiseSignature2021,
  Bls12381G2KeyPair
} from "../src/index";

import { signDeriveVerifyMulti } from "./utils";

const expKey1 = new Bls12381G2KeyPair(expExampleBls12381KeyPair);
const expKey2 = new Bls12381G2KeyPair(expExampleBls12381KeyPair2);

describe("BbsTermwise2021 and BbsTermwiseSignature2021", () => {
  it("should derive and verify a proof without range proofs", async () => {
    const vc = { ...expVCDocumentForRangeProof };
    const hiddenUris: string[] = [];

    await signDeriveVerifyMulti(
      [
        { vc, revealDocument: expRevealDocumentWithoutRangeProof, key: expKey1 }
      ],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

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

  it("should derive and verify multiple proofs including range proofs", async () => {
    const vc1 = { ...expVCDocumentForRangeProof };
    const vc2 = { ...expVCDocumentForRangeProof2 };
    const hiddenUris = [
      "https://example.org/credentials/12345678",
      "https://example.org/credentials/abcdefgh",
      "https://example.org/cityA"
    ];

    await signDeriveVerifyMulti(
      [
        {
          vc: vc1,
          revealDocument: expRevealDocumentForRangeProof,
          key: expKey1
        },
        {
          vc: vc2,
          revealDocument: expRevealDocumentForRangeProof2,
          key: expKey2
        }
      ],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should derive and verify a proof including some invalid integers", async () => {
    const vc = { ...expVCDocumentForRangeProofInvalid };
    const hiddenUris: string[] = [];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: expRevealDocumentForRangeProof2, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });
});
