package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/sessions"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type VersionInfo struct {
	Version      string `json:"version"`
	ReleaseNotes string `json:"release_notes"`
}

var (
	currentVersion VersionInfo
	mutex          sync.Mutex
	store          *sessions.CookieStore
	client         mqtt.Client
)

const (
	UploadDir       = "./uploads"
	OldVersionsDir  = "./old_versions"
	VersionInfoFile = "./version_info.json"
	SessionName     = "ota-session"
)

func init() {
	// Oturumda kullanacağımız tipleri kaydediyoruz
	gob.Register(User{})
}

type User struct {
	Username string
}

func main() {

	// MQTT broker'a bağlan
	/* client = connectToMQTTBroker("tcp://13.50.156.161:1883", "ota-server") */

	loadVersionInfo()

	// Session store oluştur
	store = sessions.NewCookieStore([]byte("super-secret-key")) // Gizli anahtarınızı daha güvenli yapın
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 1 hafta
		HttpOnly: true,
	}

	// Statik dosyaları sunmak için
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Rotaları tanımla
	http.HandleFunc("/", authMiddleware(indexHandler)) // Kök dizin, index.html'i sunar
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/upload", authMiddleware(uploadHandler))
	http.HandleFunc("/check", checkHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/download_file", downloadFileHandler)

	fmt.Println("Sunucu çalışıyor: http://localhost:8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Sunucu başlatılamadı:", err)
	}

	// MQTT client'in bağlı kalmasını sağlamak için sonsuz döngü
	select {}
}

func versionStringtoInt(versionString string) ([]int, error) {

	parts := strings.Split(versionString, ".")

	if len(parts) != 3 {
		return nil, fmt.Errorf("Geçersiz versiyon numarası: %s", versionString)
	}

	version := make([]int, len(parts))
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			fmt.Println("Hata:", err)
			return nil, err
		}
		version[i] = num
	}
	return version, nil
}

// MQTT broker'a bağlanma fonksiyonu
/* func connectToMQTTBroker(broker string, clientID string) mqtt.Client {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(clientID)

	// Bağlantı sağlandığında yapılacak işlemler
	opts.OnConnect = func(c mqtt.Client) {
		fmt.Println("MQTT sunucusuna bağlanıldı")
		// Versiyon kontrolü için "ota/check_update" başlığını dinliyoruz
		if token := c.Subscribe("ota/check_update", 0, checkVersionHandler); token.Wait() && token.Error() != nil {
			fmt.Println("Abonelik hatası:", token.Error())
		}
	}

	// MQTT client'ı oluştur
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		fmt.Println("MQTT bağlantı hatası:", token.Error())
		os.Exit(1) // Hata durumunda uygulamayı durdur
	}

	return client
} */

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// 404 Not Found
		http.NotFound(w, r)
		return
	}

	// static/index.html dosyasını sun
	http.ServeFile(w, r, "./static/index.html")
}

// Kimlik doğrulama için middleware fonksiyonu
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, SessionName)
		if err != nil {
			fmt.Println("Oturum alınırken hata oluştu:", err)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		user, ok := session.Values["user"].(User)
		if !ok || user.Username != "admin" {
			// Giriş yapılmamış, login sayfasına yönlendir
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		// Giriş yapılmış, işlemi devam ettir
		next.ServeHTTP(w, r)
	}
}

// Login sayfası ve giriş işlemi
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Hata mesajı kontrolü
		errorMessage := ""
		if r.URL.Query().Get("error") == "1" {
			errorMessage = "Kullanıcı adı veya şifre hatalı!"
		}

		// Login sayfasını göster
		tmpl, err := template.ParseFiles("./templates/login.html")
		if err != nil {
			http.Error(w, "Şablon yüklenirken hata oluştu", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, map[string]interface{}{
			"ErrorMessage": errorMessage,
		})
		return
	}

	if r.Method == "POST" {
		// Form verilerini işle
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "admin" && password == "admin" {
			// Başarılı giriş
			session, _ := store.Get(r, SessionName)
			session.Values["user"] = User{Username: username}
			err := session.Save(r, w)
			if err != nil {
				fmt.Println("Oturum kaydedilirken hata oluştu:", err)
				http.Error(w, "Sunucu hatası", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound) // "/" yoluna yönlendir
		} else {
			// Başarısız giriş
			http.Redirect(w, r, "/login?error=1", http.StatusFound)
		}
		return
	}

	// Diğer metotlar kabul edilmez
	http.Error(w, "Yalnızca GET ve POST istekleri kabul edilir", http.StatusMethodNotAllowed)
}

// Logout işlemi
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, SessionName)
	session.Values["user"] = nil
	session.Options.MaxAge = -1
	err := session.Save(r, w)
	if err != nil {
		fmt.Println("Oturum sonlandırılırken hata oluştu:", err)
		http.Error(w, "Sunucu hatası", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Versiyon bilgisini dosyadan yükleyen fonksiyon
func loadVersionInfo() {
	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.Open(VersionInfoFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Dosya yoksa varsayılan değer ata
			currentVersion = VersionInfo{
				Version:      "00.00.00",
				ReleaseNotes: "İlk sürüm",
			}
			saveVersionInfo() // Varsayılan değeri dosyaya kaydet
		} else {
			fmt.Println("Versiyon bilgisi dosyası açılırken hata oluştu:", err)
			os.Exit(1)
		}
	} else {
		defer file.Close()
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&currentVersion)
		if err != nil {
			fmt.Println("Versiyon bilgisi okunurken hata oluştu:", err)
			os.Exit(1)
		}
	}
}

// Versiyon bilgisini dosyaya kaydeden fonksiyon
func saveVersionInfo() {
	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.Create(VersionInfoFile)
	if err != nil {
		fmt.Println("Versiyon bilgisi dosyası oluşturulurken hata oluştu:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(&currentVersion)
	if err != nil {
		fmt.Println("Versiyon bilgisi kaydedilirken hata oluştu:", err)
	}
}

func compareVersions(version1, version2 []int) int {
	for i := 0; i < len(version2); i++ {
		if version2[i] > version1[i] {
			return 1
		} else if version2[i] < version1[i] {
			return -1
		}
	}
	return 0
}

// Yeni versiyon dosyalarını yüklemek için endpoint
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Yalnızca POST isteği kabul edilir", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(32 << 20) // 32 MB max memory
	if err != nil {
		http.Error(w, "Multipart form parsing hatası", http.StatusBadRequest)
		return
	}

	versionStr := r.FormValue("version")
	releaseNotes := r.FormValue("release_notes")

	version, err := versionStringtoInt(versionStr)
	if err != nil {
		http.Error(w, "Geçersiz versiyon numarası", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "Hiçbir dosya yüklenmedi", http.StatusBadRequest)
		return
	}
	currentVersionInt, err := versionStringtoInt(currentVersion.Version)

	// Eski versiyonu arşivle
	compareVersions := compareVersions(currentVersionInt, version)

	if compareVersions == 0 || compareVersions < 0 {
		http.Error(w, "Yüklenen versiyon mevcut versiyondan küçük veya eşit olamaz", http.StatusBadRequest)
		return
	} else if compareVersions > 0 && directoryExists(UploadDir) {
		err := archiveOldVersion()
		if err != nil {
			http.Error(w, "Eski versiyon arşivlenirken hata oluştu: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Mevcut dosyaları sil
	os.RemoveAll(UploadDir)
	// Yükleme dizinini oluştur
	os.MkdirAll(UploadDir, os.ModePerm)

	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			http.Error(w, "Dosya açma hatası", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		outPath := filepath.Join(UploadDir, fileHeader.Filename)
		out, err := os.Create(outPath)
		if err != nil {
			http.Error(w, "Dosya kaydetme hatası", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		_, err = io.Copy(out, file)
		if err != nil {
			http.Error(w, "Dosya kopyalama hatası", http.StatusInternalServerError)
			return
		}
	}

	// Versiyon bilgisini güncelle
	mutex.Lock()
	currentVersion = VersionInfo{
		Version:      versionStr,
		ReleaseNotes: releaseNotes,
	}
	mutex.Unlock()

	// Versiyon bilgisini dosyaya kaydet
	saveVersionInfo()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Versiyon %d başarıyla yüklendi\n", version)
}

// Eski versiyonu arşivleyen fonksiyon (zip olmadan)
func archiveOldVersion() error {
	timestamp := time.Now().Format("20060102_150405")
	archiveDirName := fmt.Sprintf("version_%s_%s", currentVersion.Version, timestamp)
	archiveDirPath := filepath.Join(OldVersionsDir, archiveDirName)

	// old_versions dizinini oluştur
	os.MkdirAll(OldVersionsDir, os.ModePerm)

	// uploads dizinini old_versions altına taşı
	err := os.Rename(UploadDir, archiveDirPath)
	if err != nil {
		return err
	}

	return nil
}

// Bir dizinin var olup olmadığını kontrol eden fonksiyon
func directoryExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// Versiyon kontrolü için endpoint
func checkHandler(w http.ResponseWriter, r *http.Request) {
	clientVersionStr := r.URL.Query().Get("version")
	clientVersion, err := versionStringtoInt(clientVersionStr)
	if err != nil {
		http.Error(w, "Geçersiz versiyon numarası", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	currentVersionInt, err := versionStringtoInt(currentVersion.Version)

	updateAvailable := compareVersions(currentVersionInt, clientVersion)

	response := map[string]interface{}{
		"update_available": updateAvailable,
		"current_version":  currentVersion.Version,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

/* func checkVersionHandler(client mqtt.Client, msg mqtt.Message) {
	// Gelen mesajın verisini alıyoruz (client'ın gönderdiği versiyon bilgisi)
	log.Print("Burdayım işte bur da yımmmm !!!!")
	clientVersionStr := string(msg.Payload())
	fmt.Printf("Gelen mesaj: %s\n", clientVersionStr)
	clientVersion, err := strconv.Atoi(clientVersionStr)
	if err != nil {
		fmt.Println("Geçersiz versiyon numarası:", clientVersionStr)
		return
	}

	// Mutex ile currentVersion'ı güvenli şekilde okuyoruz
	mutex.Lock()
	updateAvailable := currentVersion.Version > clientVersion
	mutex.Unlock()

	// Cihaza geri döneceğimiz yanıt
	response := map[string]interface{}{
		"update_available": updateAvailable,
		"current_version":  currentVersion.Version,
	}

	// Yanıtı JSON formatına çevirip MQTT üzerinden geri gönderiyoruz
	responsePayload, err := json.Marshal(response)
	if err != nil {
		fmt.Println("Yanıt JSON formatına dönüştürülemedi:", err)
		return
	}

	// Yanıtı ilgili başlığa gönderiyoruz
	token := client.Publish("ota/update_response", 0, false, responsePayload)
	token.Wait()
} */

// Dosya listesini döndürmek veya dosya indirmek için endpoint
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// uploads dizinindeki dosyaların listesini döndür
		files, err := os.ReadDir(UploadDir)
		if err != nil {
			http.Error(w, "Dosyalar okunamadı", http.StatusInternalServerError)
			return
		}

		var fileNames []string
		for _, file := range files {
			if !file.IsDir() {
				fileNames = append(fileNames, file.Name())
			}
		}

		response := map[string]interface{}{
			"files": fileNames,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Yalnızca GET isteği kabul edilir", http.StatusMethodNotAllowed)
	}
}

// Belirli bir dosyayı indirmek için endpoint
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		http.Error(w, "Dosya adı belirtilmedi", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(UploadDir, fileName)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Dosya bulunamadı", http.StatusNotFound)
		return
	}

	// Dosyayı indirme için sun
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	http.ServeFile(w, r, filePath)
}
