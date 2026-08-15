async function importCore() {
  return import("@actions/core");
}

export type ActionsCore = Awaited<ReturnType<typeof importCore>>;

let corePromise: Promise<ActionsCore> | undefined;

export function getCore(): Promise<ActionsCore> {
  corePromise ??= importCore();
  return corePromise;
}
