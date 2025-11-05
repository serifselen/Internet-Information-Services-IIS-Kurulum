TEKNİK DOKÜMAN: WINDOWS SERVER 2025 ÜZERİNDE WEB SERVER (IIS) KURULUMU VE WEB SİTESİ EKLEME

Bu doküman, Windows Server 2025 Standard Evaluation sisteminde Web Server (IIS) rolünün kurulumunu ve yeni bir web sitesi eklemeyi adım adım açıklar. Tüm işlemler Server Manager arayüzü üzerinden gerçekleştirilir. Görseller "Images/" dizininde numaralandırılmıştır.

---

## 1. ÖN GEREKSİNİMLER VE HAZIRLIK

### Sistem Gereksinimleri
- **İşletim Sistemi:** Windows Server 2025 Standard/Datacenter
- **Bellek:** Minimum 2 GB (Önerilen 4+ GB)
- **Depolama:** Minimum 10 GB boş alan
- **Ağ:** Statik IP adresi ve DNS yapılandırması

### Ağ Yapılandırması
```powershell
# Statik IP ayarlama
New-NetIPAddress -IPAddress "192.168.31.100" -PrefixLength 24 -DefaultGateway "192.168.31.1" -InterfaceAlias "Ethernet"

# DNS sunucusu ayarlama
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "127.0.0.1"

# Sunucu ismini ayarlama
Rename-Computer -NewName "IIS-SERVER" -Restart
```

---

## 2. WEB SERVER (IIS) KURULUMU

### Adım 1: Server Manager Ana Ekranı
![Adım 1](Images/1.png)

**Teknik Detaylar:**
- Server Manager otomatik olarak başlar
- Sol üst köşede "QUICK START" bölümünde "Add roles and features" bağlantısı bulunur
-Rol bazlı kurulum için temel arayüz

✅ IIS kurulumuna başlamak için **"Add roles and features"** bağlantısına tıklayın.

**PowerShell Alternatifi:**
```powershell
# Server Manager'ı PowerShell'den başlatma
servermanager
```

---

### Adım 2: "Add Roles and Features Wizard" Başlatma
![Adım 2](Images/2.png)

**Kritik Ön Kontroller:**
- ✅ Statik IP yapılandırması doğrulanmalı
- ✅ DNS çözümlemesi test edilmeli
- ✅ Güncel Windows Update'ler kontrol edilmeli

**Teknik Doğrulama Komutları:**
```powershell
# IP yapılandırmasını kontrol et
Get-NetIPConfiguration

# DNS çözümlemesini test et
Test-NetConnection -ComputerName "www.microsoft.com" -Port 80

# Windows Update durumunu kontrol et
Get-WindowsUpdateLog
```

💡 Bu sayfa yalnızca bilgilendiricidir. **Next** butonuna tıklayarak devam edin.

---

### Adım 3: Kurulum Türü Seçimi
![Adım 3](Images/3.png)

**Kurulum Türleri Detayı:**
- **Role-based or feature-based installation**: Lokal veya remote sunucuya rol ekleme
- **Remote Desktop Services installation**: RDS farm dağıtımı için

✅ **"Role-based or feature-based installation"** seçeneğini işaretleyin.  
**Next** butonuna tıklayın.

**PowerShell ile Rol Ekleme:**
```powershell
# Web Server (IIS) rolünü PowerShell ile ekleme
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
```

---

### Adım 4: Hedef Sunucu Seçimi
![Adım 4](Images/4.png)

**Sunucu Seçim Teknik Detayları:**
- **Server Pool**: Mevcut yönetilen sunucular listesi
- **Offline Sunucular**: Erişilemeyen sunucular gri görünür
- **IPv6 Desteği**: Windows Server 2025 IPv6'yı tam destekler

✅ Kurulum yapılacak sunucu zaten seçili gelir. Doğru sunucuyu seçtiğinizden emin olduktan sonra **Next** butonuna tıklayın.

**Sunucu Bilgilerini Doğrulama:**
```powershell
# Sunucu bilgilerini görüntüleme
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, CsDomain
```

---

### Adım 5: Web Server (IIS) Rolü Seçimi
![Adım 5](Images/5.png)

**Yüklenen Bileşenler:**
- **Web Server**: Çekirdek web sunucusu hizmetleri
- **Common HTTP Features**: Temel HTTP özellikleri
- **Static Content**: Statik içerik desteği
- **Default Document**: Varsayılan belge desteği
- **Directory Browsing**: Dizin listeleme
- **HTTP Errors**: Hata sayfaları
- **Security**: Güvenlik bileşenleri
- **Request Filtering**: İstek filtreleme
- **Health and Diagnostics**: Sistem sağlık kontrolü

**Teknik Özellikler:**
- **HTTP.sys**: Windows HTTP API'si
- **Application Pools**: Uygulama havuzları
- **Default Web Site**: Varsayılan web sitesi

✅ **"Include management tools (if applicable)"** seçeneği otomatik işaretlenir.  
Açılan pencerede **Add Features** butonuna tıklayıp **Next** butonuna geçin.

---

### Adım 6: Kurulum Onaylama
![Adım 6](Images/6.png)

**Kurulum Bileşenleri Listesi:**
```
Web Server (IIS)
├── Common HTTP Features
│   ├── Static Content
│   ├── Default Document
│   ├── Directory Browsing
│   └── HTTP Errors
├── Security
│   └── Request Filtering
└── Health and Diagnostics
```

**Kurulum Seçenekleri:**
- ☐ Export configuration settings
- ☐ Specify an alternate source path
- ☐ Restart the destination server automatically if required

**PowerShell ile Kurulum:**
```powershell
# Tüm IIS bileşenlerini kurma
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
```

✅ **Install** butonuna tıklayarak kurulumu başlatın.

---

### Adım 7: Kurulum İlerleme Durumu
![Adım 7](Images/7.png)

**Kurulum Aşamaları:**
1. **Binary Copy**: IIS binary dosyalarının kopyalanması
2. **Configuration**: Web sunucusu yapılandırması
3. **Service Installation**: IIS hizmetlerinin kurulumu
4. **Feature Registration**: Öne çıkan özelliklerin kaydı

**Kurulum Süresi:** 2-5 dakika

🔄 Kurulum tamamlandığında **"Installation succeeded"** mesajı görüntülenir.  
**Close** butonuna tıklayarak sihirbazı kapatın.

---

## 3. IIS MANAGER ARAYÜZÜNE ERİŞİM

### Adım 8: IIS Manager'a Erişim
![Adım 8](Images/8.png)

**Erişim Yolları:**
- **Start Menu → Windows Tools → Internet Information Services (IIS) Manager**
- **Start → Run → inetmgr**
- **Server Manager → Tools → Internet Information Services (IIS) Manager**
- **PowerShell:** `& inetmgr`

**Konsol Yapısı:**
```
IIS Manager
├── Connections
│   ├── SERVER (local)
│   │   ├── Application Pools
│   │   ├── Sites
│   │   │   └── Default Web Site
│   │   └── Content
└── Actions
```

**Temel Özellikler:**
- **Connections**: Sunucu ve sitelerin hiyerarşisi
- **Actions**: Seçilen nesne için eylemler
- **Sites**: Web sitelerinin yönetimi
- **Application Pools**: Uygulama havuzları

✅ IIS Manager açıldığında **"Default Web Site"** varsayılan olarak **Started** durumunda olacaktır.

---

## 4. WEB SİTESİ EKLEME

### Adım 9: Yeni Web Sitesi Oluşturma
![Adım 9](Images/9.png)

**Yeni Site Ekleme:**
1. **Sites** klasörüne sağ tıklayın
2. **Add Website...** seçeneğini seçin

**Sağ Tık Menü Seçenekleri:**
- **Add Website...**: Yeni web sitesi ekleme
- **Add FTP Site...**: FTP sitesi ekleme
- **Add Application...**: Uygulama ekleme
- **Refresh**: Listeyi yenileme

**PowerShell Alternatifi:**
```powershell
# Yeni web sitesi oluşturma
New-WebSite -Name "iletisim" -PhysicalPath "C:\inetpub\wwwroot" -Port 80 -HostHeader "iletisim.serifselen.com"
```

---

### Adım 10: Web Sitesi Yapılandırması
![Adım 10](Images/10.png)

**Site Yapılandırma Parametreleri:**
- **Site name:** `iletisim`
- **Application pool:** `iletisim` (yeni veya mevcut)
- **Physical path:** `C:\inetpub\wwwroot`
- **Binding:**
  - Type: `http`
  - IP address: `All Unassigned`
  - Port: `80`
  - Host name: `iletisim.serifselen.com`

**Ek Seçenekler:**
- ✅ **Start Website immediately**: Siteyi hemen başlatma
- **Connect as...**: Farklı kimlik bilgileriyle bağlanma
- **Test Settings...**: Bağlantı testi

**Hosts Dosyası Düzenleme:**
```
# hosts dosyasına eklenmesi gereken satır
192.168.31.100  iletisim.serifselen.com
```

✅ Tüm bilgileri girdikten sonra **OK** butonuna tıklayın.

---

### Adım 11: Yeni Web Sitesi Listesi
![Adım 11](Images/11.png)

**Site Listesi Görünümü:**
```
Name      ID  Status  Binding         Path
iletisim  2   Started http:*:80:      C:\inetpub\wwwroot
Default   1   Started http:*:80:      %SystemDrive%\inetpub\wwwroot
```

**Site Durumları:**
- **Started**: Çalışıyor
- **Stopped**: Durdurulmuş
- **Starting**: Başlatılıyor
- **Stopping**: Durduruluyor

**PowerShell ile Site Kontrolü:**
```powershell
# Tüm web sitelerini listeleme
Get-WebSite | Format-Table Name, State, Port, PhysicalPath
# Yeni siteyi kontrol etme
Get-WebSite -Name "iletisim" | Format-List *
```

---

## 5. KURULUM SONRASI İŞLEMLER

### 5.1. Test Sayfası Oluşturma
```powershell
# Test sayfası oluşturma
"<!DOCTYPE html>
<html>
<head>
<title>IIS Kurulumu Başarılı</title>
</head>
<body>
<h1>Windows Server 2025 Üzerinde IIS Kurulumu</h1>
<p>Bu web sitesi IIS Manager arayüzü ile oluşturulmuştur.</p>
</body>
</html>" | Out-File -FilePath "C:\inetpub\wwwroot\index.html"
```

### 5.2. Tarayıcı ile Test
- Tarayıcıya `http://iletisim.serifselen.com` yazın
- Varsayılan test sayfası görüntülenmelidir
- "HTTP Error 403.14 - Forbidden" hatası alınırsa:
  ```powershell
  # Default Document eklenmesi
  Add-WebConfigurationProperty -Filter "/system.webServer/defaultDocument/files" -Name "add" -Value @{value="index.html"}
  ```

---

## 6. SIK KARŞILAŞILAN SORUNLAR VE ÇÖZÜMLER

### 6.1. Web Sitesi Erişilemiyor
**Belirtiler:**
- Tarayıcıda "This site can't be reached" hatası
- HTTP 503 hata kodu

**Çözüm:**
```powershell
# IIS hizmetlerini yeniden başlatma
Restart-Service W3SVC
Restart-Service WAS
# Application pool durumunu kontrol etme
Get-WebAppPoolState -Name "iletisim"
# Application pool başlatma
Start-WebAppPool -Name "iletisim"
```

### 6.2. Host Name ile Erişim Sorunu
**Belirtiler:**
- IP adresi ile erişim çalışıyor
- Host name ile erişim sağlanamıyor

**Çözüm:**
```powershell
# DNS kaydı oluşturma
Add-DnsServerResourceRecordA -Name "iletisim" -ZoneName "serifselen.com" -IPv4Address "192.168.31.100"
# Hosts dosyasına ekleme
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "192.168.31.100  iletisim.serifselen.com"
```

### 6.3. Yetki Sorunları
**Belirtiler:**
- "Access is denied" hatası
- İzin sorunları

**Çözüm:**
```powershell
# Dizin izinlerini ayarlama
icacls "C:\inetpub\wwwroot" /grant "IIS_IUSRS:(OI)(CI)(RX)"
icacls "C:\inetpub\wwwroot" /grant "IUSR:(OI)(CI)(RX)"
```

---

## 7. DOKÜMAN BİLGİLERİ

| Özellik | Değer |
|---------|-------|
| **Yazar** | Serif SELEN |
| **Tarih** | 5 Kasım 2025 |
| **Versiyon** | 1.0 |
| **Platform** | VMware Workstation Pro 17 |
| **İşletim Sistemi** | Windows Server 2025 Standard Evaluation |
| **Etki Alanı** | `serifselen.com` |
| **Web Sitesi** | `iletisim.serifselen.com` |
| **Lisans** | Evaluation (180 gün) |

> ⚠️ Bu doküman **eğitim ve test ortamları** içindir. Üretimde lisanslı yazılım ve güvenlik önlemleri kullanılmalıdır.

> 📧 **Destek İçin:** mserifselen@gmail.com  
> 🔗 **GitHub Repository:** https://github.com/serifselen/Windows-Server-2025-Kurulum
```