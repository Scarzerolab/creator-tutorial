import { issuer } from "@trustvc/trustvc";
import { writeFileSync } from "fs";
import { join } from "path";
import { writeEnvVariable } from "./utils";

const { issueDID, CryptoSuite } = issuer;

const main = async () => {
  if (!process.env.API_KEY) {
    throw new Error("API_KEY is required.");
  }

  const issuedDidWeb = await issueDID({
    domain: process.env.DOMAIN,
    type: CryptoSuite.EcdsaSd2023,
    apiKey: process.env.API_KEY,
  });

  // Write the wellKnownDid to a JSON file
  const outputPath = join(process.cwd(), 'did.json');
  writeFileSync(
    outputPath,
    JSON.stringify(issuedDidWeb.wellKnownDid, null, 2)
  );
  console.log('DID document has been written to ./did.json');

  // write issuedDidWeb.didKeyPairs into .env as DID_KEY_PAIRS key
  writeEnvVariable('DID_KEY_PAIRS', JSON.stringify(issuedDidWeb.didKeyPairs));
}
main();