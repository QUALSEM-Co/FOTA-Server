# Dosya Yönetim Sistemi

Bu proje, kullanıcıların dosya yükleyebileceği, versiyon kontrolü yapabileceği ve dosya indirebileceği basit bir dosya yönetim sistemi sağlar.

## Giriş Yapma

1. Tarayıcınızda `http://localhost:8080/login` adresine gidin.
2. Kullanıcı adı ve şifreyi girerek giriş yapın.

## Dosya Yükleme

1. Giriş yaptıktan sonra `/upload` sayfasına yönlendirilirsiniz.
2. Dosyaları sürükleyip bırakabilir veya "Dosya Ekle" butonunu kullanarak dosya seçebilirsiniz.
3. Dosyaları seçtikten sonra versiyon numarası ve sürüm notlarını girin.
4. "Yüklemeyi Tamamla" butonuna tıklayarak dosyaları sunucuya yükleyin.

## Versiyon Kontrolü

İstemciler, `/check?version=X` endpoint'ine istek yaparak güncelleme olup olmadığını kontrol edebilirler.

Örnek kullanım:

```bash
curl http://localhost:8080/check?version=1
```
## Yanıt örneği:

json

`{
  "update_available": true
}`
## Dosya Listesi Alma ve İndirme
Mevcut dosyaların listesini almak için /download endpoint'ine GET isteği gönderin:

```bash

curl http://localhost:8080/download
```
## Yanıt örneği:


`{
  "files": ["dosya1.bin", "dosya2.bin", "config.json"]
}`
Belirli bir dosyayı indirmek için  `/download_file?file=dosya_adı` endpoint'ini kullanabilirsiniz:

```bash
curl -O http://localhost:8080/download_file?file=dosya1.bin
```

