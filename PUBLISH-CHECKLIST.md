# Publishing warden 0.2.0 (for Dan)

You do the upload yourself, signed in to npm. Nothing here has been run for you.
Version to release: **0.2.0**. It is not on npm yet (only an empty 0.0.1 placeholder is). It is a first
real release, so nothing breaks for existing users.

## Before you start

1. Check you are signed in to the right npm account: `npm whoami` should print `decnutz`.
2. Check you can publish under the `@decnutz` name: `npm access list packages` should list it,
   or the first publish will tell you.
3. In the repo, on branch `expert-2`, run the tests: `go test ./...` (takes a few minutes).
   Everything must say `ok`.
4. Read the README top to bottom once. The Status line should say 0.2.0 and Calas Automations Inc.

## Build all six packages (takes 10 to 30 minutes the first time)

```
scripts/build-npm.sh
```

It builds a package for each system (Linux, Mac and Windows, Intel and ARM), checks that the version
numbers match, and runs a small self-test. The files appear in `npm/dist/`.

## Check what you are about to send

```
tar -xzOf npm/dist/warden/decnutz-warden-0.2.0.tgz package/package.json
```

Look for: `"name": "@decnutz/warden"`, `"version": "0.2.0"`, `"author": "Calas Automations Inc."`,
`"access": "public"`. Do the same for one platform package, for example
`npm/dist/warden-linux-x64/decnutz-warden-linux-x64-0.2.0.tgz`.

## Upload (order matters: the six system packages first, the main package last)

```
cd npm/dist/warden-linux-x64    && npm publish
cd ../warden-linux-arm64        && npm publish
cd ../warden-darwin-x64         && npm publish
cd ../warden-darwin-arm64       && npm publish
cd ../warden-win32-x64          && npm publish
cd ../warden-win32-arm64        && npm publish
cd ../warden                    && npm publish
```

`npm publish` may ask for your one-time code. The packages are marked public already. If npm says a
version already exists, stop and ask; a published version can never be replaced.

## After it is up

1. In an empty folder: `npx @decnutz/warden demo`. You should see the tour end with "OK" and "DETECTED".
2. `npm install -g @decnutz/warden`, then `warden about`. It should say Maintained by Calas Automations Inc.
3. In the repo README, the line "once 0.2.0 is published" can now be simplified.
4. Tag the release yourself (`git tag v0.2.0`) when you are happy. Nobody has done that for you.

## Things to decide

- The npm name stays `@decnutz/warden` (plain `warden` on npm and PyPI belongs to other people). If you
  would rather have a company-named scope, decide before this first release: moving later means a new
  package name.
- The Windows and the two ARM builds have never been run on real machines. The README says so. Say
  "experimental" if anyone asks.
