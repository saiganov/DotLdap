# Releasing

Packages go to [nuget.org](https://www.nuget.org/packages/DotLdap.Testing) from the `publish` job of
[`ci.yml`](.github/workflows/ci.yml), only for a pushed `v*` tag and only after the tests passed on Linux, Windows
and macOS. The job uses [nuget.org Trusted Publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing):
no API key is stored anywhere. GitHub's OIDC token is traded for a key that lives one hour.

## Once: set up publishing

1. **nuget.org trusted publishing policy.** Sign in to nuget.org, open your user name → **Trusted Publishing** →
   **Create**, and fill in:
   - Repository owner: `saiganov`
   - Repository: `DotLdap`
   - Workflow file: `ci.yml`
   - Environment: `nuget`

   The package ID `DotLdap.Testing` is free on nuget.org (checked on 2026-11-25); the first push creates it under
   the account that owns the policy.
2. **Repository secret `NUGET_USER`.** GitHub → Settings → Secrets and variables → Actions → New repository
   secret: `NUGET_USER` = your nuget.org user name (not the e-mail).
3. **Environment `nuget`** (optional, recommended). GitHub → Settings → Environments → `nuget` (it is created by the
   first tagged run, or create it by hand): add yourself under **Required reviewers** and limit **Deployment
   branches and tags** to `v*` tags. Every release then waits for one click.

## Every release

1. Pick the version. Until 1.0 every release is a pre-release: `0.1.0-preview.1`, `0.1.0-preview.2`, then
   `0.2.0-preview.1` and so on.
2. In `Directory.Build.props`, set `VersionPrefix` to the version without the suffix (`0.1.0`). The publish job
   refuses a tag that does not start with it.
3. In `RELEASE_NOTES.md`, make sure there is a `#### 0.1.0 (preview) ####` section (heading = `#### ` + VersionPrefix
   + space). Packing fails without it; it becomes the package's release notes and the GitHub release text.
4. In `src/DotLdap.Testing`, move every line of `PublicAPI.Unshipped.txt` (except the `#nullable enable` header) to
   the end of `PublicAPI.Shipped.txt`, so that `Unshipped` lists only what changes after this release.
5. Merge these changes to `main` and wait for green CI.
6. Tag the merge commit and push the tag:

   ```bash
   git switch main && git pull
   git tag v0.1.0-preview.1
   git push origin v0.1.0-preview.1
   ```

7. Approve the `nuget` environment in the Actions run if you set up reviewers. The job packs with
   `-p:Version=0.1.0-preview.1`, pushes the `.nupkg` and `.snupkg` to nuget.org and creates a GitHub release (marked
   pre-release when the version has a `-suffix`) with the packages and the release notes.
8. nuget.org indexes a new version in a few minutes; until then `dotnet add package` may not find it.

A version number on nuget.org can be unlisted but never reused: if a release is wrong, fix it and tag the next
pre-release number. Rerunning the job for the same tag is safe (`--skip-duplicate`), but the GitHub release step
fails if the release already exists; delete it first.

## After 1.0

Set `PackageValidationBaselineVersion` in `Directory.Build.props` to the last released version, so that `pack` fails
on a breaking change to the public API, and drop the `-preview` tags.
