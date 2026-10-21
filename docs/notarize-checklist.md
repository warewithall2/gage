# Optional macOS signing and notarization checklist

This is for a future release only, if Owen chooses to buy an Apple Developer
Program membership. It is not needed for local testing, and no account or
certificate is included with this project. These commands assume a macOS
release machine, an Apple Silicon `gage` binary already built for macOS, and
the finished `Gage.app` from `packaging/macos/make-app.sh`.

1. **Confirm the signing identity.** In Xcode's Accounts settings, create or
   download a **Developer ID Application** certificate. Then run:

   ```sh
   security find-identity -v -p codesigning
   ```

   This proves the certificate and private key are installed in the login
   keychain. Copy the exact `Developer ID Application: ... (TEAMID)` identity
   shown; do not use the ad-hoc `-` identity for notarization.

2. **Sign the executable with the hardened runtime.** Set `IDENTITY` to that
   exact identity and run:

   ```sh
   codesign --force --options runtime --timestamp --sign "$IDENTITY" \
     --identifier sh.gage.app Gage.app/Contents/MacOS/gage
   ```

   This signs the bundled Rust executable for Developer ID distribution.

3. **Sign the app bundle.**

   ```sh
   codesign --force --options runtime --timestamp --sign "$IDENTITY" \
     --identifier sh.gage.app Gage.app
   ```

   This seals the app bundle, including its launcher, plist, and resources.

4. **Verify the signature locally.**

   ```sh
   codesign --verify --deep --strict --verbose=2 Gage.app
   spctl --assess --type execute --verbose=2 Gage.app
   ```

   The first command verifies the code signature and sealed resources. The
   second asks Gatekeeper to assess the app before notarization; a rejection
   here means to fix signing or bundle contents before uploading.

5. **Create a notarization profile once.** Choose a private profile name and
   enter the Apple ID, app-specific password, and Team ID when prompted:

   ```sh
   xcrun notarytool store-credentials GageNotary \
     --apple-id "$APPLE_ID" --team-id "$TEAM_ID"
   ```

   This stores credentials in the local keychain. Never put the password or
   keychain contents in source control or a build log.

6. **Package the signed app for upload.**

   ```sh
   ditto -c -k --keepParent Gage.app Gage-notarize.zip
   ```

   This creates the ZIP archive that will be submitted to Apple's notary
   service.

7. **Submit and wait for Apple's result.**

   ```sh
   xcrun notarytool submit Gage-notarize.zip --keychain-profile GageNotary \
     --wait --output-format json
   ```

   Continue only when the result is `Accepted`. If rejected, fetch the
   submission log using the returned ID:

   ```sh
   xcrun notarytool log SUBMISSION_ID --keychain-profile GageNotary notary-log.json
   ```

   The log identifies the issue to correct; rebuild and sign again before
   resubmitting.

8. **Staple Apple's ticket and verify it.**

   ```sh
   xcrun stapler staple Gage.app
   xcrun stapler validate Gage.app
   spctl --assess --type execute --verbose=2 Gage.app
   ```

   These commands attach Apple's ticket to the app, verify the stapled ticket,
   and confirm Gatekeeper accepts the final artifact offline.

9. **Make the distribution archive.**

   ```sh
   ditto -c -k --keepParent Gage.app Gage-macOS.zip
   ```

   This is the archive to publish. Retain the accepted submission ID and the
   signature and Gatekeeper verification output with the release record.
