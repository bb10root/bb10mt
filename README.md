# BB10 MultiTool

**BB10 MultiTool** (v0.6.0.0 beta 4) is a comprehensive command-line utility for working with BlackBerry 10 images, file systems (QNX6, RCFS), firmware structures (QCFM, Autoloaders), unpacked BAR packages, and connected devices (flashing, device info, connection management).

## 🚀 Installation & Shell Completion

To enable autocompletion for `bb10mt` in your shell, export the completion script using one of the commands below:

* **Bash:**
  ```bash
  bb10mt --completion-file > myapp-completion.sh
  source myapp-completion.sh
  ```

* **PowerShell:**
  ```powershell
  bb10mt --completion-file-pwsh > myapp-completion.ps1
  . .\myapp-completion.ps1
  ```

---

## 📋 Global Options

| Option | Description |
| :--- | :--- |
| `-h, --help` | Show command help |
| `--help-complete` | Show complete CLI reference |
| `--completion-file` | Output Bash completion script |
| `--completion-file-pwsh` | Output PowerShell completion script |
| `-v, --version` | Show version information |

> **Tip:** For details on a specific command or subcommand, run:
> ```bash
> bb10mt <command> --help
> ```

---

## 🛠 Commands & Subcommands

### 1. `qnx6` — QNX6 File System Manipulations

Utilities for mounting, creating, repairing, and scripting QNX6FS images.

* **`mount`** — Mount a QNX image
  * `-m, --mountpoint` *(Required)*: Target mounting point
  * `-i, --image` *(Required)*: Path to QNX6FS image file
  * `-f, --foreground`: Run in foreground *(Default: `false`)*
  * `-d, --debug`: Output FUSE debug information *(Default: `false`)*

* **`compact`** — Compact a QNX6 image
  * `-i, --image` *(Required)*: Path to QNX6FS image file

* **`mkfs`** — Create a new QNX6 image
  * `-i, --image` *(Required)*: Path to QNX6FS image file
  * `-b, --blocks`: Total block count *(Default: `10240`)*
  * `-n, --inodes`: Total inode count *(Default: `1024`)*
  * `-s, --block-size`: Block size, must be a multiple of 512 *(Default: `4096`)*

* **`fsck`** — Check and verify QNX6 image integrity
  * `-i, --image` *(Required)*: Path to QNX6FS image file
  * `-f, --fix`: Automatically fix errors *(Default: `false`)*

* **`script`** — Execute a script on a QNX6 image
  * `-i, --image` *(Required)*: Path to QNX6FS image file
  * `-s, --script` *(Required)*: Path to script file
  * `-d, --debloat`: Create a debloat script *(Default: `false`)*
  * `-b, --blacklist`: Comma-separated list of app names/IDs to remove

---

### 2. QCFM Containers (`unpack` / `pack`)

* **`unpack`** — Extract files from a QCFM container
  * `-c, --container` *(Required)*: Path to container file
  * `-o, --output`: Output directory

* **`pack`** — Pack files into a QCFM container
  * `-c, --container` *(Required)*: Target container file
  * `-i, --input`: Input files (comma-separated)
  * `-l, --list`: File containing a list of input files
  * `, --versions`: QCFM version(s) (comma-separated, *Default: `2`*)
  * `-s, --sign`: Add a fake signature *(Default: `false`)*
  * `-f, --fast`: Include empty blocks *(Default: `false`)*

---

### 3. Device & Flashing Operations

Allows connecting to BlackBerry 10 devices over USB or network, flashing images/firmwares, inspecting hardware information, and managing device state.

* **`split`** — Split an Autoloader binary into components
  * `-i, --input` *(Required)*: Input autoloader file
  * `-o, --output`: Output directory

* **`flash`** — Flash file(s) directly to connected device
  * `-i, --input`: Input files to flash (comma-separated)
  * `-l, --list`: Input files list
  * `, --versions`: QCFM version(s) (comma-separated, *Default: `1,2`*)
  * `-r, --loaders`: Path to RAM-loaders directory *(Default: `loaders`)*
  * `-d, --delay`: RAM-loader delay in milliseconds *(Default: `1000`)*

* **`info`** — Display information about the connected device
  * `-d, --delay`: RAM-loader delay in milliseconds *(Default: `1000`)*

* **`loader`** — Probe all available RAM loaders
  * `-d, --delay`: RAM-loader delay in milliseconds *(Default: `1000`)*

* **`connect`** — Connect to a BlackBerry device over USB or network
  * `-i, --ip`: Target IP address
  * `-p, --password` *(Required)*: Device password
  * `-k, --sshPublicKey` *(Required)*: Path to RSA public key to install on the device

* **`nuke`** — Completely wipe/nuke the connected device

---

### 4. `autoloader` — Autoloader Manipulations

* **`create`** — Build a custom autoloader
  * `-o, --output`: Output file *(Default: `autoloader.exe`)*
  * `-c, --cap`: Path to `cap.exe` file *(Default: `cap.exe`)*
  * `-i, --input`: Input files (comma-separated)
  * `-l, --list`: File listing input files
  * `, --versions`: CAP tail version *(Default: `2`)*

* **`extract`** — Extract `cap.exe` from an existing autoloader
  * `-i, --input` *(Required)*: Target Autoloader file
  * `-c, --cap`: Output cap file name *(Default: `cap.exe`)*

* **`loaders`** — Extract RAM-loaders from CAP, CFP, or autoloader files
  * `-i, --input` *(Required)*: Path to `cap.exe` or `cfp.exe` file
  * `-o, --output`: Output directory *(Default: `ramloaders`)*

---

### 5. `bar` — Unpacked BAR Package Operations

* **`template`** — Create a new BAR directory template
  * `-p, --path` *(Required)*: Path to base directory
  * `-n, --name` *(Required)*: BAR package name

* **`update`** — Update hashes in `MANIFEST.MF`
  * `-p, --path` *(Required)*: Path to unpacked BAR directory

* **`ids`** — Generate new IDs in `MANIFEST.MF`
  * `-p, --path` *(Required)*: Path to unpacked BAR directory

* **`install`** — Install an unpacked BAR into a mount point
  * `-p, --path` *(Required)*: Path to unpacked BAR directory
  * `-m, --mount` *(Required)*: Path to mount point

---

### 6. `rcfs` — RCFS Image Operations

* **`modify`** — Modify an RCFS image
  * `-i, --image` *(Required)*: RCFS image file
  * `-c, --corrupt`: Corrupt a file inside RCFS
  * `-s, --script`: Path to execution script

* **`extract`** — Extract files from an RCFS image
  * `-i, --image` *(Required)*: RCFS image file
  * `-o, --out` *(Required)*: Output directory path

* **`vmdk`** — VMware disk image manipulation
  * `-i, --image` *(Required)*: RCFS image file
  * `-s, --script`: Path to script file

---

### 7. `raw` — Raw Flash Data Processing

* **`dump`** — Split a raw flash image into individual partitions
  * `-i, --input` *(Required)*: Input file path
  * `-o, --output`: Output directory
  * `-m, --mct`: MCT offset value

* **`nvram`** — Split NVRAM image into individual data blocks
  * `-i, --input` *(Required)*: Input file path
  * `-o, --output`: Output directory

---

### 8. `batch` — Automated Processing

* **`batch`** — Perform automated batch processing on an autoloader image
  * `-i, --input` *(Required)*: Path to autoloader file
  * `-s, --script` *(Required)*: Path to script file
  * `-o, --output`: Output folder
  * `-c, --compact`: Compact final image *(Default: `false`)*