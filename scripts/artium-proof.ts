type GuardCallback = <Args extends unknown[]>(callback: (...args: Args) => void) => (...args: Args) => void;

export async function runArtiumProof(proof: (guard: GuardCallback) => Promise<void>, cleanup: () => Promise<void>): Promise<void> {
  const failure = Promise.withResolvers<never>();
  let callbackFailure: { error: unknown } | undefined;
  const guard: GuardCallback = callback => (...args) => {
    try {
      callback(...args);
    } catch (error) {
      callbackFailure ??= { error };
      failure.reject(error);
    }
  };
  try {
    await Promise.race([Promise.resolve().then(() => proof(guard)), failure.promise]);
  } finally {
    // Cleanup stops active proof work and its event sources before the error escapes.
    await cleanup();
    if (callbackFailure) throw callbackFailure.error;
  }
}
