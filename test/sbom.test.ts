import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { toSbom } from "../src/sbom";

// ── Fallback: manifest files (no lock file present) ──────────────────────────

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

// ── package-lock.json (v2/v3) ─────────────────────────────────────────────────

test("toSbom reads transitive deps from package-lock.json v3", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-lock-v3-"));
  fs.writeFileSync(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "myapp", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/express": { version: "4.18.2" },
        "node_modules/express/node_modules/debug": { version: "2.6.9" },
      },
    }),
  );
  // package.json present but should be ignored in favour of lock file
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ dependencies: { lodash: "^4.0.0" } }),
  );

  const sbom = JSON.parse(toSbom(dir));
  const purls: string[] = sbom.components.map((c: { purl: string }) => c.purl).sort();

  assert.deepEqual(purls, [
    "pkg:npm/debug@2.6.9",
    "pkg:npm/express@4.18.2",
    "pkg:npm/lodash@4.17.21",
  ]);
});

test("toSbom reads scoped packages from package-lock.json v3", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-lock-scoped-"));
  fs.writeFileSync(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/@babel/core": { version: "7.23.0" },
        "node_modules/@types/node": { version: "20.11.0" },
      },
    }),
  );

  const sbom = JSON.parse(toSbom(dir));
  const purls: string[] = sbom.components.map((c: { purl: string }) => c.purl).sort();

  assert.deepEqual(purls, [
    "pkg:npm/@babel/core@7.23.0",
    "pkg:npm/@types/node@20.11.0",
  ]);
});

test("toSbom deduplicates identical name@version in package-lock.json v3", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-lock-dedup-"));
  fs.writeFileSync(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/ms": { version: "2.1.3" },
        "node_modules/debug/node_modules/ms": { version: "2.1.3" }, // same version
      },
    }),
  );

  const sbom = JSON.parse(toSbom(dir));
  assert.equal(sbom.components.length, 1);
  assert.equal(sbom.components[0].purl, "pkg:npm/ms@2.1.3");
});

// ── package-lock.json (v1) ────────────────────────────────────────────────────

test("toSbom reads nested transitive deps from package-lock.json v1", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-lock-v1-"));
  fs.writeFileSync(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: "4.17.21" },
        express: {
          version: "4.18.2",
          dependencies: {
            debug: { version: "2.6.9" },
          },
        },
      },
    }),
  );

  const sbom = JSON.parse(toSbom(dir));
  const purls: string[] = sbom.components.map((c: { purl: string }) => c.purl).sort();

  assert.deepEqual(purls, [
    "pkg:npm/debug@2.6.9",
    "pkg:npm/express@4.18.2",
    "pkg:npm/lodash@4.17.21",
  ]);
});

// ── Pipfile.lock ──────────────────────────────────────────────────────────────

test("toSbom reads default and develop sections from Pipfile.lock", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-pipfile-"));
  fs.writeFileSync(
    path.join(dir, "Pipfile.lock"),
    JSON.stringify({
      default: {
        flask: { version: "==3.0.0" },
        requests: { version: "==2.31.0" },
      },
      develop: {
        pytest: { version: "==7.4.0" },
      },
    }),
  );
  // requirements.txt present but should be ignored
  fs.writeFileSync(path.join(dir, "requirements.txt"), "flask==2.0.0\n");

  const sbom = JSON.parse(toSbom(dir));
  const purls: string[] = sbom.components.map((c: { purl: string }) => c.purl).sort();

  assert.deepEqual(purls, [
    "pkg:pypi/flask@3.0.0",
    "pkg:pypi/pytest@7.4.0",
    "pkg:pypi/requests@2.31.0",
  ]);
});

test("toSbom strips == prefix from Pipfile.lock versions", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-pipfile-ver-"));
  fs.writeFileSync(
    path.join(dir, "Pipfile.lock"),
    JSON.stringify({ default: { django: { version: "==5.0.1" } }, develop: {} }),
  );

  const sbom = JSON.parse(toSbom(dir));
  assert.equal(sbom.components[0].version, "5.0.1");
  assert.equal(sbom.components[0].purl, "pkg:pypi/django@5.0.1");
});

test("toSbom deduplicates packages appearing in both Pipfile.lock sections", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sbom-pipfile-dedup-"));
  fs.writeFileSync(
    path.join(dir, "Pipfile.lock"),
    JSON.stringify({
      default: { certifi: { version: "==2024.2.2" } },
      develop: { certifi: { version: "==2024.2.2" } },
    }),
  );

  const sbom = JSON.parse(toSbom(dir));
  assert.equal(sbom.components.length, 1);
});

