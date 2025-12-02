<img width="1358" height="725" alt="image" src="https://github.com/user-attachments/assets/465030dd-39f4-4393-a6f3-d089689453df" />

# Android Adware Cleaner (ADB + Google GenAI)

A small desktop GUI tool (Tkinter) that connects to an Android device via ADB, lists installed packages, and helps you spot and remove potential adware.  
Optionally, it can callGoogle Gemini (via `google-genai`) to analyse apps and highlight suspicious ones.

---

## Features

-ADB integration
  - Check ADB status.
  - Connect viaUSB orwireless.
  - Show connecteddevice ID.
  - List allinstalled packages.
  - Viewrecent / foreground apps.

-Adware detection (Gemini)
  - Enter yourGoogle GenAI API key and select aGemini model (e.g. `gemini-2.5-flash`).
  - Use the“Ad appears: Scan now (K)” button to trigger a scan when you see an unexpected ad.
  - View AI-flagged apps under the“Gemini Suspects” tab.

-Package management
  - Filter packages by name.
  - Choose between:
    -Uninstall (user 0) – uninstall for the primary user.
    -Uninstall (full) – fully remove the package (if allowed by the system).
  - Optional“Dry run” mode to simulate actions without actually uninstalling.

-Status log
  - A log area at the bottom shows ADB version, connection messages, and other diagnostics.

---

## Requirements

-Python 3.x
-ADB (Android Debug Bridge) installed  
  - On Windows, this is usually from theAndroid Platform Tools (`adb.exe`).
  - ADB should either be in your `PATH` or in the folder referenced by the script.
-Android device
  - Developer options enabled.
  -USB debugging turned on.
-Google GenAI API key  
  - From Google AI Studio / Google Cloud (for Gemini access).
- Python packages:
  - Standard library: `tkinter`, `subprocess`, `threading`, `json`, `os`, `re`
  - External: `google-genai`

### `requirements.txt`

Create a file named `requirements.txt` with:

```text
google-genai
````

Install with:

```bash
pip install -r requirements.txt
```

(You donot need to install `tkinter` separately on most standard Python distributions; it ships with Python.)

---

## Installation

1.Install Python (if you have not already).

2.Install ADB (Android Platform Tools) and confirm it works:

   ```bash
   adb version
   ```

3.Clone / download this project into a folder of your choice.

4. Create and activate a virtual environment (optional but recommended), then install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

1.Start ADB & connect your device

   * EnableUSB debugging on your phone.
   * Connect via USB and accept the debugging dialog.
   * Alternatively, connect wirelessly if configured.

2.Run the program

   From the project folder:

   ```bash
   python android_adware_cleaner.py
   ```

   (Replace `android_adware_cleaner.py` with the actual name of your main script if different.)

3.Check ADB status

   * The bottom log panel should show something like:

     > ADB OK: Android Debug Bridge version …

4.Set up Gemini

   * In the“Gemini (google-genai)” section:

     * Paste yourAPI key.
     * Choose amodel (e.g. `gemini-2.5-flash`).
     * Click“Test API” to verify that the key and model work.

5.Scan apps

   * Click“List Installed” to populate theInstalled Packages tab.
   * UseFilter to narrow by package name.
   * When you see an unwanted ad on your device, press“Ad appears: Scan now (K)”
     (or use theK keyboard shortcut).
   * Use“Scan Recent (no AI)” if you only want to inspect recent / foreground apps without Gemini.

6.Review and uninstall

   * Check the“Gemini Suspects” tab for apps the model considers suspicious.
   * Select a package and choose:

     *“Uninstall (user 0)”, or
     *“Uninstall (full)”.
   * If“Dry run” is ticked, commands will be shown butnot actually executed.

7.Restart ADB (optional)

   * If ADB gets stuck, click“Restart ADB” and try again.

---

## Notes & Limitations

* The tool relies on metadata available via ADB (package names, etc.); Gemini’s output isadvisory, not a guarantee.
* Some system or vendor apps cannot be fully uninstalled; ADB may only disable them or fail with a permission error.
* Tested onWindows (as in the screenshot); other platforms should work as long as Tkinter and ADB are available.

---

## Disclaimer

Use this tool at your own risk. Uninstalling system or critical apps can cause instability.
Always double-check packages before removal, and consider keepingDry run enabled until you are confident with the results.

```
```
