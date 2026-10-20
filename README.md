# 🛡️ LightSecure-Guard

> A lightweight, modern security and vulnerability inspection engine built with Rust, designed for high performance and precise system auditing.

---

## 🚀 Features (المميزات الرئيسية)

* **⚡ Ultra-Fast Performance:** Written in Rust for maximum execution speed and minimal resource footprint.
* **🔍 Smart Hashing & Caching:** Utilizes SHA-256 hashing combined with local JSON caching (`scan_cache.json`) to skip unchanged files and dramatically speed up recurring scans.
* **🌐 Cloud CVE Integration:** Simulates secure TLS 1.3 encrypted queries against live vulnerability databases to check file integrity and threat signatures.
* **🔒 Clean & Safe Architecture:** Strictly engineered to avoid local bloat, ensuring zero sensitive data exposure.

---

## 📁 Project Structure (هيكلية المشروع)

```text
lightsecure_guard/
├── src/
│   └── main.rs          # Core security engine and scanning logic
├── Cargo.toml           # Rust package manifest and dependencies
├── .gitignore           # Strict exclusion rules (ignoring target/, cache, etc.)
└── scan_cache.json      # Local persistent scan state cache