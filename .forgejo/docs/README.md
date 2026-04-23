# Launch Pad Forgejo APK Release Workflow

Use this checklist when maintaining this repository's `.forgejo/` APK release
workflow. The detailed workflow behavior is documented in
[`release-apk-workflow.md`](release-apk-workflow.md).

## Plan

1. Keep `.forgejo/workflows/release-apk.yml` aligned with the Launch Pad package,
   artifact names, and GitHub repository.
2. Confirm the app can read release signing values from environment variables.
3. Add the required Forgejo secrets.
4. Validate the workflow syntax and the local release build before pushing a tag.

## Implementation

### Project Names

The Launch Pad workflow uses these project-specific values:

```bash
keystore_path="${temp_dir}/launchpad-release.keystore"
export RELEASE_KEYSTORE_PATH="${temp_dir}/launchpad-release.keystore"
cp "${apk_files[0]}" "dist/launchpad-${tag}.apk"
asset_path="dist/launchpad-${tag}.apk"
release_name="Launch Pad ${tag}"
owner="firebadnofire"
repo="LaunchPad"
```

Use the exact GitHub repository name. GitHub repository paths are case-sensitive
enough that mismatches can produce confusing 404 errors.

### Remove Copied App Dependencies

Search for assumptions from the source project:

```bash
rg -n 'tr''apmaster|simple''wallet|P''WA|m''ilestones|M''ilestones' .forgejo
```

Remove any source-app setup steps that the target app does not need. For a normal
native Android app, there should not be a step that fetches another app or web
asset before Gradle runs.

### Wire Release Signing in Gradle

The workflow exports these values before `assembleRelease`:

```text
RELEASE_KEYSTORE_PATH
KEYSTORE_PASSWORD
KEY_ALIAS
KEY_PASSWORD
```

The Android app must use them in its release signing config. If the target app
does not already do that, add a conditional signing config to the module
`build.gradle.kts`:

```kotlin
val releaseKeystorePath = System.getenv("RELEASE_KEYSTORE_PATH")
val releaseKeystorePassword = System.getenv("KEYSTORE_PASSWORD")
val releaseKeyAlias = System.getenv("KEY_ALIAS")
val releaseKeyPassword = System.getenv("KEY_PASSWORD")
val hasReleaseSigning = listOf(
    releaseKeystorePath,
    releaseKeystorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }

signingConfigs {
    if (hasReleaseSigning) {
        create("release") {
            storeFile = file(releaseKeystorePath!!)
            storePassword = releaseKeystorePassword
            keyAlias = releaseKeyAlias
            keyPassword = releaseKeyPassword
        }
    }
}

buildTypes {
    release {
        if (hasReleaseSigning) {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

Keep the app's existing `isMinifyEnabled`, `proguardFiles`, and other release
settings. Do not hardcode passwords, aliases, tokens, or keystore paths.

### Configure Secrets

Add these secrets in Forgejo for the target repository or owning organization:

```text
KEY_ALIAS
KEY_PASSWORD
KEYSTORE_BASE64
KEYSTORE_PASSWORD
GH_KEY
```

`GH_KEY` must be able to create the GitHub repository if it is missing, push Git
refs to it, create and edit releases, and upload release assets in
`firebadnofire/LaunchPad`. For a classic token, use `repo` scope. For a
fine-grained token, grant enough account/organization access to create the
repository and repository `Contents: Read and write` for the destination after it
exists.

Generate `KEYSTORE_BASE64` from the keystore file with:

```bash
base64 -i release.keystore
```

Use the output as the secret value. Do not commit the keystore.

## Validation

Run these checks in the target repository before pushing a release tag:

```bash
ruby -e 'require "yaml"; YAML.load_file(".forgejo/workflows/release-apk.yml"); puts "yaml ok"'
rg -n 'tr''apmaster|simple''wallet|P''WA|m''ilestones|M''ilestones' .forgejo
GRADLE_USER_HOME="$PWD/.gradle" sh ./gradlew --no-daemon tasks --all
GRADLE_USER_HOME="$PWD/.gradle" sh ./gradlew --no-daemon assembleRelease
```

The local `assembleRelease` may produce an unsigned APK if signing secrets are not
present. That is acceptable for local validation. The CI job should produce a
signed APK when the secrets are configured.

After validation, push a version tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

If GitHub release publishing fails with a 404, check the `owner` and `repo`
values first, then verify that `GH_KEY` has access to that repository.
