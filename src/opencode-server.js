// OpenCode's `server` entry (package export "./server"). OpenCode 2 runs `setup`; OpenCode 1.x loaders that read
// "./server" run `server` (a default object with an id). Older 1.x loaders read the package root, src/opencode.js,
// which keeps its single named export for them.
import { JevGuard } from "./opencode.js";
import { setup } from "./opencode-v2.js";

export default { id: "jev-guard", server: JevGuard, setup };
