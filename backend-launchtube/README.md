# Vireca Backend - Launchtube Edition

Launchtube platformu için özel olarak geliştirilmiş Vireca sağlık veri yönetimi backend API'si.

## Özellikler

### 🚀 Launchtube Entegrasyonu
- Launchtube kullanıcı kimlik doğrulama
- Platform-specific JWT token yönetimi
- Kullanıcı profil entegrasyonu
- Rol tabanlı erişim kontrolü

### 🔐 Gelişmiş Güvenlik
- JWT tabanlı kimlik doğrulama
- Launchtube platform imza doğrulama
- CORS koruması
- Rate limiting
- Dosya boyutu ve tip kontrolü

### 📊 Sağlık Veri Yönetimi
- IPFS tabanlı güvenli dosya depolama
- Metadata desteği
- Şifrelenmiş veri anahtarları
- Zaman sınırlı erişim izinleri

### 🌐 API Endpoints

#### Kimlik Doğrulama
- `POST /auth/launchtube` - Launchtube ile giriş
- `GET /health` - API durumu

#### Veri Yönetimi
- `POST /prepare/register-data` - Yeni veri kaydı
- `POST /prepare/grant-access` - Erişim izni verme
- `POST /prepare/revoke-access` - Erişim iptal
- `POST /transaction/submit` - İşlem gönderme

## Kurulum

### 1. Bağımlılıkları Kurun

```bash
pip install -r requirements.txt
```

### 2. Çevre Değişkenlerini Ayarlayın

`env.example` dosyasını `.env` olarak kopyalayın:

```bash
cp env.example .env
```

Gerekli değerleri doldurun:

```env
# Launchtube Platform Configuration
LAUNCHTUBE_API_KEY="your_launchtube_api_key"
LAUNCHTUBE_BASE_URL="https://api.launchtube.xyz"
LAUNCHTUBE_NETWORK="testnet"

# Stellar Network Configuration
PINATA_JWT="your_pinata_jwt_key"
CONTRACT_ID="your_soroban_contract_id"
NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
RPC_URL="https://soroban-testnet.stellar.org:443"

# Security Configuration
JWT_SECRET_KEY="your-super-secret-jwt-key"
```

### 3. Uygulamayı Çalıştırın

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API dokümantasyonu: http://localhost:8000/docs

## Launchtube Entegrasyonu

### Kullanıcı Kimlik Doğrulama

```python
# 1. Launchtube ile giriş yap
response = requests.post("/auth/launchtube", {
    "public_key": "GA...",
    "signature": "...",
    "message": "..."
})

# 2. JWT token al
token = response.json()["access_token"]

# 3. Diğer API çağrılarında kullan
headers = {"Authorization": f"Bearer {token}"}
```

### Veri Kaydetme

```python
# Dosya ve metadata ile veri kaydet
files = {"file": open("medical_report.pdf", "rb")}
data = {
    "owner_public_key": "GA...",
    "encrypted_key_for_owner": "base64_encrypted_key",
    "metadata": {
        "title": "Kan Testi Sonucu",
        "data_type": "lab_result",
        "tags": ["kan", "test", "2024"]
    }
}

response = requests.post(
    "/prepare/register-data", 
    data=data, 
    files=files,
    headers=headers
)
```

### Erişim İzni Verme

```python
# Doktora erişim izni ver
response = requests.post("/prepare/grant-access", {
    "granter_public_key": "GA...",
    "doctor_public_key": "GB...",
    "ipfs_hash": "Qm...",
    "encrypted_key_for_doctor": "base64_key",
    "duration_in_ledgers": 17280,  # 24 saat
    "access_reason": "Rutin kontrol için"
}, headers=headers)
```

## Güvenlik Özellikleri

### 1. Çok Katmanlı Doğrulama
- Launchtube kullanıcı doğrulama
- JWT token kontrolü
- Stellar imza doğrulama
- Platform imza kontrolü

### 2. Veri Koruma
- End-to-end şifreleme
- IPFS güvenli depolama
- Metadata şifreleme
- Erişim logları

### 3. Uyumluluk
- HIPAA (Health Insurance Portability and Accountability Act)
- GDPR (General Data Protection Regulation) 
- KVKK (Kişisel Verilerin Korunması Kanunu)

## Hata Kodları

| Kod | Açıklama |
|-----|----------|
| 404001 | Kullanıcı bulunamadı |
| 400001 | Geçersiz imza |
| 403001 | İzin reddedildi |
| 413001 | Dosya çok büyük |
| 415001 | Desteklenmeyen dosya tipi |
| 429001 | Rate limit aşıldı |
| 500001 | IPFS yükleme hatası |
| 500002 | Stellar ağ hatası |
| 500003 | Launchtube API hatası |

## Desteklenen Dosya Tipleri

- PDF dökümanlar
- JPEG/PNG görseller
- TIFF tıbbi görüntüler
- DICOM dosyaları
- JSON veri dosyaları
- Düz metin dosyaları

## Rate Limiting

- Varsayılan: 100 istek/dakika
- Authenticated users: 500 istek/dakika
- Premium users: 1000 istek/dakika

## Monitoring ve Logging

Uygulama otomatik olarak:
- API isteklerini loglar
- Hata durumlarını takip eder
- Performance metriklerini toplar
- Güvenlik olaylarını kayıt eder

## Destek

Launchtube platformu ile ilgili sorunlar için:
- Launchtube Discord: https://discord.gg/launchtube
- Email: support@launchtube.xyz
- Documentation: https://docs.launchtube.xyz

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. 