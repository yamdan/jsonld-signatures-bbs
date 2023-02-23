import jsigs from "jsonld-signatures";

import {
  exampleBls12381KeyPair,
  customLoader,
  testDocumentForBound
} from "./__fixtures__";
import { Bls12381G2KeyPair, BoundBbsTermwiseSignature2022 } from "../src/index";

const key = new Bls12381G2KeyPair(exampleBls12381KeyPair);

const commitmentForTestDocument = new Uint8Array(
  Buffer.from(
    "rOCB1WMUZ1aVdo4Z2XujfFe9C42g68s04Y68yoCD86cNwT4og3RyD3q6FkicuRjw",
    "base64"
  )
);

describe("BoundBbsTermwiseSignature2022", () => {
  it("should sign with jsigs", async () => {
    const signed = await jsigs.sign(testDocumentForBound, {
      suite: new BoundBbsTermwiseSignature2022({
        key,
        proverCommitment: commitmentForTestDocument
      }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(signed).toBeDefined();
  });
});
