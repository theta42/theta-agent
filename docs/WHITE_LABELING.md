# White-labeling the agent

theta-agent displays the organization name in three places: the Windows logon
tile, the desktop tray icon, and the tray tooltip. The name comes from the
directory (pushed via the WebSocket config frame) and can be overridden locally
in `agent.yml`.

## Organization name: pushed by the directory

The directory sends `organization_name` in the WebSocket `config` frame on every
agent connection. The agent stores it and uses it for:

- **Windows logon tile** — replaces the `OpenCredential` display name
- **Desktop tray** — the tooltip and title show the organization name

The directory's white-label name is set in the Directory admin UI
(Configuration → Branding) and replicates to all spokes automatically. This is
the preferred way to brand agents — set it once, every agent sees it.

## Local override: agent.yml

For standalone deployments or per-agent overrides, set in `agent.yml`:

```yaml
credential_provider_name: "MyOrg Login"
```

The directory-pushed name wins when both are set. Empty/absent falls back to the
vendor default (`OpenCredential <version>` for the tile, `Theta Agent` for the
tray).

or at install time:

```
theta-agent-windows-amd64-setup.exe /SILENT /SERVER_URL=... /JOIN_KEY=... /CP_NAME="MyOrg Login"
```

Notes:

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
