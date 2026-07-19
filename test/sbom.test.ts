import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { toSbom } from "../src/sbom";

test("toSbom detects npm and pip dependencies", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-test-"));
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({
      dependencies: { lodash: "^4.17.21" },
      devDependencies: { typescript: "~5.6.3" },
    }),
  );
  fs.writeFileSync(path.join(dir, "requirements.txt"), "flask==3.0.0\nrequests>=2.31.0\n");

  const sbom = JSON.parse(toSbom(dir));
  const purls = sbom.components.map((c: { purl: string }) => c.purl).sort();

  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.equal(sbom.specVersion, "1.5");
  assert.deepEqual(purls, [
    "pkg:npm/lodash@4.17.21",
    "pkg:npm/typescript@5.6.3",
    "pkg:pypi/flask@3.0.0",
    "pkg:pypi/requests@2.31.0",
  ]);
});

test("toSbom detects Maven dependencies", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-maven-test-"));
  fs.writeFileSync(
    path.join(dir, "pom.xml"),
    `
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.1</version>
    </dependency>
  </dependencies>
</project>
`,
  );

  const sbom = JSON.parse(toSbom(dir));

  assert.deepEqual(sbom.components, [
    {
      type: "library",
      name: "org.springframework:spring-core",
      version: "6.1.1",
      purl: "pkg:maven/org.springframework/spring-core@6.1.1",
    },
  ]);
});
