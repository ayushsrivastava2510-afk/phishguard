# 📱 PhishGuard Native Android Application (Kotlin + Jetpack Compose)

Autonomous mobile threat sentinel engineered in modern **Kotlin** with **Jetpack Compose**, bringing real-time **SMS Smishing Interception**, **TRAI DLT Header Auditing**, and **Section 65B BSA Digital Evidence** directly onto Android smartphones.

---

## 🌟 Key Native Mobile Capabilities

1. **⚡ Zero-Click Real-Time SMS Interception:**
   - Registers a system `BroadcastReceiver` (`android.provider.Telephony.SMS_RECEIVED`).
   - When an incoming SMS arrives, the app analyzes it on-device in under 5 milliseconds.
   - If a high-severity threat (banking fraud, power cut panic, or `.apk` malware dropper) is detected, it immediately pushes a **Heads-Up High-Priority Alert Notification** warning the user before they click.

2. **🛡️ On-Device TRAI DLT Verification Engine:**
   - Native Kotlin port of India's **TRAI TCCCPR 2018** regulation.
   - Verifies 6-character alphanumeric registered entity headers (`AX-SBINB`, `AD-HDFCBK`).
   - Flags unauthenticated personal 10-digit mobile SIMs (`+91 9xxxxxxxxx`) posing as banks (+45 risk penalty).
   - Detects cross-border virtual numbers (`+62`, `+84`, `+1`) used in Telegram task fraud.

3. **📦 Android APK Trojan Dropper Interception:**
   - Detects direct links delivering Android application packages (`.apk`) outside Google Play (e.g. fake *mParivahan*, *SBI YONO* banking trojans).

4. **🏛️ 1-Tap DoT Chakshu & 1930 Cybercrime Reporting:**
   - Formats a formal police and telecom complaint complete with a **Section 65B BSA Cryptographic SHA-256 Digest**.
   - One-tap "Copy to Clipboard" for immediate submission to **Sanchar Saathi (Chakshu)** and **1930 / cybercrime.gov.in**.

5. **🎨 GeekPay Enterprise Fintech Aesthetic:**
   - High-trust slate-navy card architecture (`#0B0F19`, `#1E293B`).
   - Smooth animated circular risk gauges (0 to 100).
   - Dual-Vector Toggle: `[ 📱 Mobile SMS Sentinel ]` vs `[ 📧 Email Threat Sentinel ]`.

---

## 🚀 Opening in Android Studio

1. Open **Android Studio** (Ladybug / Hedgehog or newer).
2. Select **Open** and choose the `android/` folder inside this repository:
   ```
   c:\Users\Ayush\OneDrive\Desktop\phishguard (1)\android
   ```
3. Android Studio will automatically sync the Gradle project using Gradle Version Catalog (`libs.versions.toml`).
4. Select an Android Emulator or connected physical device and click **Run (Shift + F10)**.

---

## 🏗️ Building via Command Line

* **Build Debug APK:**
  ```bash
  cd android
  ./gradlew assembleDebug      # Linux / macOS
  gradlew.bat assembleDebug    # Windows
  ```
  The resulting APK will be generated at:
  `android/app/build/outputs/apk/debug/app-debug.apk`

* **Execute Kotlin Unit Tests:**
  ```bash
  gradlew.bat test
  ```

---

## 📋 System Requirements
* **Language:** Kotlin 2.1.0
* **UI Toolkit:** Jetpack Compose (Material 3)
* **Minimum Android Version:** Android 8.0 Oreo (API level 26)
* **Target Android Version:** Android 15 (API level 35)
* **Architecture:** Offline-first, on-device heuristics with optional cloud SOC synchronization.
