import { Document } from "jsonld/jsonld-spec";
import { SuiteSignOptions } from "./SuiteSignOptions";
import { VerifyProofOptions } from "./VerifyProofOptions";
import { VerifyProofResult } from "./VerifyProofResult";

export interface LinkedDataSignature {
  sign(document: Document, options: SuiteSignOptions): Promise<object>;
  verify(
    document: Document,
    options: VerifyProofOptions
  ): Promise<VerifyProofResult>;
}
