/* eslint-disable @typescript-eslint/no-explicit-any */
import { getProofs, getTypeInfo } from "./utilities";
import jsonld from "jsonld";
import { SECURITY_PROOF_URL } from "jsonld-signatures";

/**
 * Derives a proof from a document featuring a supported linked data proof
 *
 * NOTE - This is a temporary API extending JSON-LD signatures
 *
 * @param proofDocument A document featuring a linked data proof capable of proof derivation
 * @param revealDocument A document of the form of a JSON-LD frame describing the terms to selectively derive from the proof document
 * @param options Options for proof derivation
 */
export const deriveProof = async (
  proofDocument: any,
  revealDocument: any,
  { hiddenUris, suite, documentLoader, skipProofCompaction, nonce }: any
): Promise<any> => {
  if (Array.isArray(proofDocument)) {
    throw new TypeError("proofDocument should be an object not an array.");
  }

  const derivedProofs = await deriveProofMulti(
    [[proofDocument, revealDocument]],
    {
      hiddenUris,
      suite,
      documentLoader,
      skipProofCompaction,
      nonce
    }
  );

  return derivedProofs[0];
};

/**
 * Derives proofs from documents featuring supported linked data proofs
 *
 * NOTE - This is a temporary API extending JSON-LD signatures
 *
 * @param documents pair(s) of two documents s.t., (1) featuring a linked data proof capable of proof derivation; and (2) JSON-LD frame describing the terms to selectively derive from the proof documents
 * @param hiddenUris URI(s) to be hidden in the derived proofs
 * @param options Options for proof derivation (* `options.suite` must implement deriveProofMulti method)
 */
export const deriveProofMulti = async (
  documents: [any, any][],
  { hiddenUris, suite, documentLoader, skipProofCompaction, nonce }: any
): Promise<any[]> => {
  if (!suite) {
    throw new TypeError('"options.suite" is required.');
  }

  if (!Array.isArray(documents)) {
    throw new TypeError("documents should be an array not an object.");
  }

  const inputDocuments = await Promise.all(
    documents.map(async ([proofDocument, revealDocument]) => {
      const { proofs, document } = await getProofs({
        document: proofDocument,
        proofType: suite.supportedDeriveProofType,
        documentLoader,
        skipProofCompaction
      });

      if (proofs.length === 0) {
        throw new Error(
          `There were not any proofs provided that can be used to derive a proof with this suite.`
        );
      }

      return { document, proof: proofs, revealDocument };
    })
  );

  const derivedProofs = await suite.deriveProofMulti({
    inputDocuments,
    documentLoader,
    hiddenUris,
    nonce
  });

  for (const derivedProof of derivedProofs) {
    if (!skipProofCompaction) {
      /* eslint-disable prefer-const */
      let expandedProof: any = {
        [SECURITY_PROOF_URL]: {
          "@graph": derivedProof.proof
        }
      };

      // account for type-scoped `proof` definition by getting document types
      const { types, alias } = await getTypeInfo(derivedProof.document, {
        documentLoader
      });

      expandedProof["@type"] = types;

      const ctx = jsonld.getValues(derivedProof.document, "@context");

      const compactProof = await jsonld.compact(expandedProof, ctx, {
        documentLoader,
        compactToRelative: false
      });

      delete compactProof[alias];
      delete compactProof["@context"];

      if (compactProof.proof === undefined) {
        throw new Error(
          "All the proofs are vanished after proof-compaction. Possibly `@context` of the reveal document (JSON-LD frame) is inconsistent with the proof suite."
        );
      }

      /**
       * removes the @included tag when multiple proofs exist because the
       * @included tag messes up the canonicalized bytes leading to a bad
       * signature that won't verify.
       **/
      if (compactProof.proof && compactProof.proof["@included"]) {
        compactProof.proof = compactProof.proof["@included"];
      }

      // add proof to document
      const key = Object.keys(compactProof)[0];
      jsonld.addValue(derivedProof.document, key, compactProof[key]);
    } else {
      delete derivedProof.proof["@context"];
      jsonld.addValue(derivedProof.document, "proof", derivedProof.proof);
    }
  }

  return derivedProofs.map((derivedProof: any) => derivedProof.document);
};

/**
 * Verifies proofs from documents featuring supported linked data proofs
 *
 * NOTE - This is a temporary API extending JSON-LD signatures
 *
 * @param documents documents featuring linked data proofs capable of proof derivation
 * @param options Options for proof derivation (* `options.suite` must implement verifyProofMulti method)
 */
export const verifyProofMulti = async (
  documents: any[],
  { suite, purpose, documentLoader, skipProofCompaction }: any
): Promise<any> => {
  if (!suite) {
    throw new TypeError('"options.suite" is required.');
  }

  if (!Array.isArray(documents)) {
    throw new TypeError("documents should be an array not an object.");
  }

  const inputDocuments = await Promise.all(
    documents.map(async (doc) => {
      const { proofs, document } = await getProofs({
        document: doc,
        proofType: suite.proofType,
        documentLoader,
        skipProofCompaction
      });

      if (proofs.length === 0) {
        throw new Error(
          `There were not any proofs provided that can be used to derive a proof with this suite.`
        );
      }

      return { document, proof: proofs };
    })
  );

  return suite.verifyProofMulti({
    inputDocuments,
    documentLoader,
    purpose
  });
};
