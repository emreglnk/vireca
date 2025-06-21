# Vireca Projesi

Vireca, blockchain tabanlı sağlık veri yönetim sistemidir. Bu sistem, hastaların sağlık verilerini güvenli bir şekilde saklamalarına ve doktorlara kontrollü erişim vermelerine olanak tanır.

## Proje Yapısı

```
vireca/
├── contracts/          # Soroban akıllı kontrat
│   ├── src/
│   │   ├── lib.rs     # Ana kontrat kodu
│   │   └── main.rs    # Binary entry point
│   └── Cargo.toml     # Rust bağımlılıkları
├── backend/           # Python FastAPI backend
│   ├── main.py        # Ana API uygulaması
│   ├── requirements.txt # Python bağımlılıkları
│   └── env.example    # Çevre değişkenleri örneği
└── README.md          # Bu dosya
```

## Kurulum

### 1. Soroban Kontratı

Öncelikle Soroban CLI'yi kurmanız gerekir:

```bash
# Soroban CLI kurulumu
cargo install --locked soroban-cli
```

Kontratı derlemek ve deploy etmek için:

```bash
cd contracts
cargo build --target wasm32-unknown-unknown --release
soroban contract deploy --wasm target/wasm32-unknown-unknown/release/vireca_contract.wasm --source alice --network testnet
```

### 2. Python Backend

Python bağımlılıklarını kurun:

```bash
cd backend

# Sanal ortam oluşturun (önerilen)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate     # Windows

# Bağımlılıkları kurun
pip install -r requirements.txt
```

### 3. Çevre Değişkenlerini Yapılandırın

`backend/env.example` dosyasını `backend/.env` olarak kopyalayın ve değerlerini doldurun:

```bash
cd backend
cp env.example .env
```

`.env` dosyasındaki değerleri kendi bilgilerinizle değiştirin:

- `PINATA_JWT`: Pinata IPFS servisinizden alacağınız JWT token
- `CONTRACT_ID`: Deploy ettiğiniz kontratın ID'si
- `NETWORK_PASSPHRASE`: Stellar test ağı için varsayılan değer
- `RPC_URL`: Soroban RPC sunucu adresi

### 4. Uygulamayı Çalıştırın

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API dokümantasyonuna şu adresten erişebilirsiniz: http://localhost:8000/docs

## API Endpoints

### Veri Kaydetme
- `POST /prepare/register-data` - Yeni sağlık verisi kaydetmek için işlem hazırlar
- `POST /transaction/submit` - İmzalı işlemi blockchain'e gönderir

### Erişim Yönetimi
- `POST /prepare/grant-access` - Doktora erişim izni vermek için işlem hazırlar
- `POST /prepare/revoke-access` - Erişim iznini iptal etmek için işlem hazırlar

## Güvenlik

- Tüm veriler IPFS'de şifrelenmiş olarak saklanır
- Şifreleme anahtarları blockchain'de güvenli şekilde tutulur
- Erişim izinleri zaman sınırlıdır
- Sadece veri sahibi erişim izni verebilir/iptal edebilir

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. 