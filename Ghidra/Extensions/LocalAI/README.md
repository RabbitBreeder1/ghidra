# Ghidra LocalAI

A deliberately simple Ghidra extension that connects the current CodeBrowser session to a
locally hosted Ollama model.

## Current features

- Dockable Swing chat panel.
- Ollama `/api/chat` support.
- Loopback-only model endpoint by default and by enforcement:
  - `127.0.0.1`
  - `localhost`
  - `::1`
- Carries the last 12 user/assistant chat messages into each request.
- Automatically attaches context from the current Ghidra cursor/function:
  - program name
  - executable format
  - language
  - cursor address
  - current function name and entry address
  - current prototype
  - current function comment
  - current EOL comment
  - current function's decompiled C
- Decompiled C is capped at 24,000 characters per request.
- AI-requested edits are only accepted when the model emits the LocalAI action protocol.
- Supported edits:
  - rename the current function
  - set the current function comment
  - set an EOL comment at the captured cursor address
- Function renames use Ghidra's `SourceType.AI`.
- Edit batches are Ghidra transactions. If one action fails, the entire AI edit batch rolls back.
- The UI has an `Allow AI edits` checkbox. Disable it for read-only chat.
- One-click DRM / protector heuristic scan using:
  - imported library names
  - defined strings
  - memory-section names
- Recognizes common indicators for Steam/SteamStub, Denuvo, VMProtect, Themida/WinLicense,
  Arxan, SecuROM, SafeDisc, StarForce, Ubisoft Connect/Uplay, and UPX.
- DRM/protector findings are added to subsequent LocalAI prompt context.
- Protection detection is evidence-based and heuristic; it does not attempt to bypass or disable DRM.
- One-click **Network / Server Scan** for preservation-oriented analysis:
  - recognized networking imports/APIs (Winsock, WinHTTP, WinINet, libcurl, OpenSSL/TLS,
    WebSocket, Steam Networking, Epic Online Services, RakNet, ENet)
  - URLs, hostnames/domains, and IPv4 addresses from defined strings
  - protocol/request markers such as HTTP headers, JSON, gRPC, Socket.IO, and API paths
  - xrefs from networking APIs and endpoint strings back to local Ghidra functions
- Network scan findings are added to subsequent LocalAI prompt context so the model can reason
  about likely login, matchmaking, telemetry, HTTP/API, socket, and server-connection code.
- Static network scanning does not capture runtime DNS, endpoints decrypted/assembled at runtime,
  dynamically loaded APIs, or custom encrypted protocols; those require dynamic tracing.
- **Analyze Game Folder**:
  - starts from the loaded program's executable directory
  - scans nearby `.exe` and `.dll` files without executing them
  - ranks modules using networking/online-service filenames and raw ASCII/UTF-16LE indicators
  - recognizes indicators for Winsock, WinHTTP/WinINet, libcurl/OpenSSL, Steam Networking,
    Epic Online Services, RakNet, ENet, GameSpy, DNS/address resolution, server browsing,
    HTTP(S)/WebSocket URLs, and common login/auth/match/lobby paths
  - reports the strongest modules to import into Ghidra next
  - feeds the ranked module report into later LocalAI chat context.
- **Preservation Analysis (AI)** one-button workflow:
  - automatically runs game-folder module analysis, DRM/protector scanning, and network/server discovery
  - finds functions referenced by network APIs/endpoints
  - looks for dynamic resolution through LoadLibrary/GetProcAddress/LdrLoadDll
  - searches for hidden networking DLL/API-name strings
  - expands one call-graph hop around strong candidates
  - ranks candidate functions
  - decompiles and sends at most the top 18 functions to the local Ollama model
  - asks Qwen to classify likely login/auth, version, matchmaking, session, telemetry,
    and real-time networking roles
  - synthesizes a persistent preservation report that becomes part of later chat context
- The one-button workflow is deliberately bounded so a large game does not trigger thousands of
  local-model requests.

## Default model

The UI defaults to:

```
qwen3-coder:30b
```

You can type any installed Ollama model name into the Model field.

## Build from this repository

This branch currently targets the Ghidra source version in this repository
(Ghidra 12.3 DEV / JDK 25).

From the repository root:

### Windows

```powershell
.\gradlew.bat -I gradle\support\fetchDependencies.gradle -DhideDownloadProgress -DnoEclipse
.\gradlew.bat buildGhidra --parallel
```

The finished Ghidra distribution is placed under:

```
build\dist\
```

The LocalAI extension archive is bundled under `Extensions/Ghidra` inside the resulting
Ghidra distribution.

## Enable LocalAI in Ghidra

1. Start the newly built Ghidra.
2. From the Project window choose **File -> Install Extensions...**
3. Enable **LocalAI** and restart Ghidra if requested.
4. Open a program in CodeBrowser.
5. Choose **File -> Configure...**
6. Enable the **LocalAIPlugin** if it is not already enabled.
7. The **Local AI** component appears as a dockable window.

## Ollama

Install Ollama separately and make sure its local service is running.

Pull the default model:

```powershell
ollama pull qwen3-coder:30b
```

The extension defaults to:

```
http://127.0.0.1:11434
```

Use **Check Ollama** in the Local AI panel before the first chat request.

## Safe test program

`examples/tiny_numbers.c` is provided under CC0-1.0 specifically for testing this extension.

Compile it without debug information, import the resulting executable into Ghidra, run normal
auto-analysis, put the cursor inside one of the small helper functions, and ask:

```
What does the current function do? Do not modify anything.
```

Then test edits:

```
Rename the current function to clamp_value and add a short function comment describing what it does.
```

Ghidra should report the rename/comment in the LocalAI transcript. The changes can also be undone
using Ghidra's normal Undo command.

## Important behavior

The model never receives the entire binary. The first version sends the current decompiled
function plus the metadata listed above.

The system prompt treats decompiled code, symbols, comments, strings, and other program content as
untrusted data rather than model instructions.

This first version intentionally rejects non-loopback Ollama hosts so analysis text cannot be sent
to a remote model endpoint by mistake.
