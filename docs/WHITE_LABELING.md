# White-labeling the Windows logon tile

When theta-agent enables directory logon on Windows, it installs the bundled
**OpenCredential** credential provider (a maintained BSD-3 fork of pGina). By
default the tile on the Windows logon screen reads `OpenCredential <version>`.
Deployments that brand the suite for their own organization can change both
the **name** under the tile today and — with one extra build step — the
**logo image**.

## Tile name: supported out of the box

The text LogonUI shows under a credential-provider tile is simply the default
value of the provider's registration key:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\<CLSID>
```

theta-agent rewrites that value for the OpenCredential provider (located by its
`InprocServer32` DLL path, not a hard-coded CLSID) whenever it seeds the
provider configuration — i.e. on `theta-agent configure-login` and whenever the
Directory pushes the LDAP config. Set in `agent.yml`:

```yaml
credential_provider_name: "MyOrg Login"
```

or at install time:

```
theta-agent-windows-amd64-setup.exe /SILENT /SERVER_URL=... /JOIN_KEY=... /CP_NAME="MyOrg Login"
```

Notes:

- Empty/absent keeps the vendor default (`OpenCredential <version>`).
- Branding is re-applied after every seed because OpenCredential's own
  installer resets its registration key on upgrade.
- A branding failure is logged but never blocks directory logon.
- The registry write requires elevation; the agent service already runs as
  SYSTEM, and `configure-login` must be run as Administrator.

## Tile logo: reserved, needs a provider rebuild

The logo bitmap is a Win32 bitmap/icon resource compiled into the provider DLL
(`OpenCredential3.dll`); LogonUI loads it from the DLL's resources, so there is
nothing to point at a file or registry value. `credential_provider_logo` exists
in `agent.yml` as a reserved field and is accepted-but-ignored until one of the
following lands:

1. **Rebuild OpenCredential with custom resources (recommended).**
   Build the fork from source with your organization's bitmap/icon resources
   (the upstream project anticipates CI builds), pin your artifact in
   `installer/windows/vendor-manifest.json`, and install it instead of the
   stock release. This keeps everything signed and reproducible.

2. **Post-install resource surgery.** Rewrite the bitmap resource inside the
   installed DLL (`UpdateResource`) as an extra installer step. This works
   without rebuilding upstream but invalidates the DLL's Authenticode
   signature and breaks on every vendor update — only sensible for
   air-gapped deployments that do not care about the signature.

Once either path ships a configurable artifact, wire it up by teaching
`maybeApplyCredentialProviderBranding` (cp_branding_windows.go) to deploy the
bitmap and drop the "reserved" warning.

## Related

- `DESIGN-WINDOWS.md` §6 — how directory logon works on Windows
- `configure_login.go` / `cp_branding_windows.go` — implementation
- Directory app → *Install Agent* → *Download binaries* tab — where operators
  grab the installer to distribute
