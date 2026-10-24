import manifest from "../tools.lock.json";

export const TOOL_LOCK_SCHEMA_VERSION = manifest.schemaVersion;
export const TOOLS = manifest.tools;
export type ToolName = keyof typeof TOOLS;

interface GitHubTool {
  repository: string;
  version: string;
  tagTemplate: string;
  assetTemplate: string;
}

interface MavenTool {
  group: string;
  artifact: string;
  extension: string;
  version: string;
}

function expandVersion(template: string, version: string): string {
  return template.replaceAll("{version}", version);
}

export function githubReleaseUrl(tool: GitHubTool): string {
  const tag = expandVersion(tool.tagTemplate, tool.version);
  const asset = expandVersion(tool.assetTemplate, tool.version);
  return `https://github.com/${tool.repository}/releases/download/${tag}/${asset}`;
}

export function mavenArtifactUrl(tool: MavenTool): string {
  const groupPath = tool.group.replaceAll(".", "/");
  const filename = `${tool.artifact}-${tool.version}.${tool.extension}`;
  return `https://repo1.maven.org/maven2/${groupPath}/${tool.artifact}/${tool.version}/${filename}`;
}

// Pinned scanner version reported for an engine. SpotBugs also loads the
// FindSecBugs plugin, whose rules produce most of its security findings.
export function engineVersion(engine: string): string | undefined {
  if (engine === "spotbugs") {
    return `${TOOLS.spotbugs.version} + findsecbugs ${TOOLS.findsecbugs.version}`;
  }
  return (TOOLS as Record<string, { version: string } | undefined>)[engine]?.version;
}
