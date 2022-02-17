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
    const vc = { ...expVCDocumentForRangeProof2 };
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

  it("should derive and verify a proof including one range proof", async () => {
    const vc = { ...expVCDocumentForRangeProof2 };
    const hiddenUris: string[] = [];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: expRevealDocumentForRangeProof2, key: expKey1 }],
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

  it("should not derive a range proof including some invalid integers", async () => {
    const vc = { ...expVCDocumentForRangeProofInvalid };
    const hiddenUris: string[] = [];

    await expect(
      signDeriveVerifyMulti(
        [{ vc, revealDocument: expRevealDocumentForRangeProof2, key: expKey1 }],
        hiddenUris,
        customLoader,
        BbsTermwiseSignature2021,
        BbsTermwiseSignatureProof2021
      )
    ).rejects.toThrowError("Failed to create proof");
  });

  it("should not derive a range proof with value out of range: 30000 notin [1, 100]", async () => {
    const vc = { ...expVCDocumentForRangeProof2 };
    const hiddenUris: string[] = [];

    const revealDocument = expRevealDocumentForRangeProof2;
    revealDocument.credentialSubject.area.range = [1, 100];

    await expect(
      signDeriveVerifyMulti(
        [{ vc, revealDocument, key: expKey1 }],
        hiddenUris,
        customLoader,
        BbsTermwiseSignature2021,
        BbsTermwiseSignatureProof2021
      )
    ).rejects.toThrowError("Failed to create proof");
  });

  it("should not derive a range proof with value out of range: 30000 notin [100000, 900000]", async () => {
    const vc = { ...expVCDocumentForRangeProof2 };
    const hiddenUris: string[] = [];

    const revealDocument = expRevealDocumentForRangeProof2;
    revealDocument.credentialSubject.area.range = [100000, 900000];

    await expect(
      signDeriveVerifyMulti(
        [{ vc, revealDocument, key: expKey1 }],
        hiddenUris,
        customLoader,
        BbsTermwiseSignature2021,
        BbsTermwiseSignatureProof2021
      )
    ).rejects.toThrowError("Failed to create proof");
  });
});
