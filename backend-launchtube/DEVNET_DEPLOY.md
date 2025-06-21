# Vireca Kontratını Devnet'e Deploy Etme Rehberi

Launchtube platformu ile Vireca akıllı kontratını Stellar Devnet'e deploy etmek için adım adım rehber.

## 🚀 Devnet Nedir?

**Stellar Devnet** (Development Network):
- ⚡ **Hızlı reset**: Periyodik olarak sıfırlanır
- 🔄 **Sürekli güncelleme**: En yeni özellikler test edilir  
- 🆓 **Ücretsiz**: Test XLM kolayca alınabilir
- 🛠️ **Geliştirme odaklı**: Hızlı iterasyon için ideal

## 📋 Ön Gereksinimler

### 1. Soroban CLI Kurulumu
```bash
# Soroban CLI'yi kurun
cargo install --locked soroban-cli

# Versiyonu kontrol edin
soroban --version
```

### 2. Stellar Cüzdan Oluşturma
```bash
# Yeni cüzdan oluştur
soroban keys generate --global alice

# Public key'i görüntüle
soroban keys address alice
```

### 3. Devnet için XLM Alma
```bash
# Friendbot'tan XLM al (devnet için)
soroban keys fund alice --network devnet
```

## 🔧 Network Yapılandırması

### Devnet Ayarları
```bash
# Devnet network'ü ekle
soroban network add \
  --global devnet \
  --rpc-url https://rpc-devnet.stellar.org:443 \
  --network-passphrase "Standalone Network ; February 2017"
```

### Network Kontrolü
```bash
# Mevcut network'leri listele
soroban network ls

# Devnet bağlantısını test et
soroban network status --network devnet
```

## 📦 Kontrat Deploy Etme

### 1. Kontratı Derle
```bash
cd contracts
cargo build --target wasm32-unknown-unknown --release
```

### 2. Kontratı Deploy Et
```bash
# WASM dosyasını deploy et
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/vireca_contract.wasm \
  --source alice \
  --network devnet
```

### 3. Contract ID'yi Kaydet
Deploy işlemi sonucunda size bir Contract ID verilecek:
```
Contract deployed successfully with ID: CABC123...XYZ789
```

Bu ID'yi `.env` dosyanızda kullanın:
```env
CONTRACT_ID="CABC123...XYZ789"
```

## 🔧 Backend Yapılandırması

### 1. Environment Ayarları
`.env` dosyasını güncelleyin:

```env
# Launchtube Platform Configuration
LAUNCHTUBE_API_KEY="your_launchtube_api_key"
LAUNCHTUBE_BASE_URL="https://api.launchtube.xyz"
LAUNCHTUBE_NETWORK="devnet"

# Stellar Network Configuration - DEVNET
PINATA_JWT="your_pinata_jwt_key"
CONTRACT_ID="CABC123...XYZ789"  # Yukarıda aldığınız ID
NETWORK_PASSPHRASE="Standalone Network ; February 2017"
RPC_URL="https://rpc-devnet.stellar.org:443"

# Security Configuration
JWT_SECRET_KEY="your-super-secret-jwt-key"
```

### 2. Backend'i Başlat
```bash
cd backend-launchtube
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## 🧪 Test Etme

### 1. Health Check
```bash
curl http://localhost:8000/health
```

Başarılı yanıt:
```json
{
  "status": "healthy", 
  "services": {
    "stellar_network": "connected",
    "launchtube_platform": "connected",
    "ipfs_gateway": "connected"
  },
  "platform": "launchtube"
}
```

### 2. Kontrat Fonksiyonlarını Test Et
```bash
# Kontrat bilgilerini görüntüle
soroban contract inspect \
  --id CABC123...XYZ789 \
  --network devnet
```

## 🌐 Network Karşılaştırması

| Özellik | Devnet | Testnet | Mainnet |
|---------|--------|---------|---------|
| **Hız** | En hızlı | Orta | En yavaş |
| **Stabilite** | Düşük (reset) | Yüksek | En yüksek |
| **Maliyet** | Ücretsiz | Ücretsiz | Ücretli |
| **Kullanım** | Development | Testing | Production |
| **XLM Alma** | Friendbot | Friendbot | Satın alma |

## 🔄 Network Değiştirme

### Testnet'e Geçiş
```env
LAUNCHTUBE_NETWORK="testnet"
NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
RPC_URL="https://soroban-testnet.stellar.org:443"
```

### Mainnet'e Geçiş
```env
LAUNCHTUBE_NETWORK="mainnet"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
RPC_URL="https://soroban-mainnet.stellar.org:443"
```

## ⚠️ Devnet Uyarıları

### 1. Data Persistence
- Devnet **periyodik olarak sıfırlanır**
- Verileriniz kaybolabilir
- Production verisi saklamayın

### 2. Performance
- Daha yavaş olabilir
- Eksperimental özellikler test edilir
- Kararsızlık yaşanabilir

### 3. Contract Lifecycle
- Kontratlar silinebilir
- Düzenli backup alın
- Test verisi kullanın

## 🚀 Production'a Geçiş

Geliştirme tamamlandığında:

1. **Testnet'e deploy edin** (son testler)
2. **Mainnet'e deploy edin** (production)
3. **DNS ve domain ayarları** yapın
4. **Monitoring ve logging** aktif edin
5. **Backup stratejisi** oluşturun

## 🔍 Debugging

### Log Kontrolü
```bash
# Backend logları
tail -f logs/vireca.log

# Stellar network durumu
soroban network status --network devnet
```

### Contract Events
```bash
# Contract event'lerini takip et
soroban events --start-ledger latest --network devnet
```

## 📞 Destek

Sorun yaşamanız durumunda:

- **Launchtube Discord**: https://discord.gg/launchtube
- **Stellar Discord**: https://discord.gg/stellardev
- **GitHub Issues**: Repository issues bölümü

## ✅ Checklist

Deploy öncesi kontrol listesi:

- [ ] Soroban CLI kuruldu
- [ ] Stellar cüzdan oluşturuldu
- [ ] Devnet XLM alındı
- [ ] Kontrat derlendi
- [ ] Network yapılandırıldı
- [ ] Environment ayarlandı
- [ ] Backend test edildi
- [ ] API endpoint'leri çalıştı

## 🎯 Sonuç

Devnet kullanarak:
- ✅ Hızlı geliştirme yapabilirsiniz
- ✅ Ücretsiz test edebilirsiniz  
- ✅ Yeni özellikler deneyebilirsiniz
- ✅ Launchtube entegrasyonunu test edebilirsiniz

**Başarılı deploy'lar! 🚀** 