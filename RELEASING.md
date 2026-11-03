# Releasing the InfraFence Agent

One release a month, plus security fixes as soon as they are ready. Every change reaches `main` through a pull request.

## Monthly release

1. **Dependencies.** At the start of the month Dependabot opens one grouped pull request per ecosystem (Go modules, GitHub Actions, Docker). The distribution matrix runs on the Go and Docker ones; for an Actions update, read the release notes of each new major version (runtime, removed inputs) before merging.
2. **Changes.** Every feature or fix pull request passes the distribution matrix on all 15 distributions (`test/distro/run.sh`) and adds its entry under `## Unreleased` in `CHANGELOG.md`, with the docs (READMEs, site docs) in the same pull request.
3. **Dashboard first.** When the release needs a dashboard change (a new field, endpoint or migration), the dashboard is released before the agent. Old dashboards must keep working with the new agent, and old agents with the new dashboard.
4. **Release pull request.** Rename `## Unreleased` to `## vX.Y.Z` in `CHANGELOG.md`. If `main` changed since the last full matrix run, run the Distro matrix workflow on `main` (Actions → Distro matrix → Run workflow) and link the run.
5. **Tag.** After the merge, tag the merge commit and push the tag:

   ```
   git fetch origin
   git tag vX.Y.Z origin/main
   git push origin vX.Y.Z
   ```

   The Release workflow builds the binaries and the image, signs them with cosign and publishes the GitHub release.
6. **Verify.** Download the assets and check `checksums.txt` and the signatures:

   ```
   sha256sum -c checksums.txt
   cosign verify-blob --key cosign.pub --signature checksums.txt.sig --insecure-ignore-tlog=true checksums.txt
   ```

   (and the same for each binary).
7. **Roll out.** Update the internal servers first, then customers update from the dashboard or by automatic updates.

## Security fixes

Dependabot alerts and security updates are on for this repository: a vulnerable dependency gets its own pull request as soon as an advisory is published, outside the monthly schedule. Same steps, without waiting for the end of the month: a pull request with the fix and its test, the matrix on all distributions, a patch release.
