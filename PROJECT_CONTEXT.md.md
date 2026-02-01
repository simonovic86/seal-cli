You are working on Seal, a command-line commitment primitive.

Seal is not a productivity tool, password manager, secure notes app, or focus app.

The core idea:
Seal allows a user to make an irreversible commitment by encrypting data such that it cannot be decrypted until a specified future time.

Design principles (non-negotiable):

No undo, cancel, extend, or early unlock.

No accounts, no authentication, no recovery flows.

No interactive prompts or “are you sure?” dialogs.

Seal must be honest about limitations (SSD shredding, clipboard clearing, backups).

Any best-effort operation must be explicit and warned.

The user is considered adversarial after sealing.

Seal’s job is not to help the user behave better.
It removes capabilities so the user cannot act, even if they want to.

Target users are technical and understand consequences.

The CLI is the authoritative interface.
GUI, widgets, or observers (if any) are secondary and read-only.

Time-based locking must rely on an external, verifiable time authority
(e.g. public randomness beacons like drand).

Do not invent features beyond what is explicitly requested.
When unsure, prefer less functionality.

This project already exists as a browser-based app; this CLI is a new incarnation of the same idea, not a new product.