package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"

	"github.com/UriMV23/crud-firebase/api" // Importa el paquete api
)

var client *firestore.Client
var authClient *auth.Client
var tmpl = template.Must(template.ParseGlob("templates/*.html"))

func initFirebase() {
	ctx := context.Background()
	opt := option.WithCredentialsFile("firebase/crud-golang-firebase-adminsdk-fbsvc-627ce1863f.json")
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		log.Fatalf("Error inicializando Firebase: %v", err)
	}

	client, err = app.Firestore(ctx)
	if err != nil {
		log.Fatalf("Error conectando a Firestore: %v", err)
	}

	authClient, err = app.Auth(ctx)
	if err != nil {
		log.Fatalf("Error inicializando Firebase Auth: %v", err)
	}

	// Inicializa la API con el cliente de Firestore
	api.Init(client)
}

func main() {
	initFirebase()

	// Rutas de la API
	http.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			api.ListItems(w, r)
		case http.MethodPost:
			api.CreateItem(w, r)
		case http.MethodPut:
			api.UpdateItem(w, r)
		case http.MethodDelete:
			api.DeleteItem(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	// Ruta para verificar la autenticación
	http.HandleFunc("/api/check-auth", CheckAuth)

	// Otras rutas (login, registro, etc.)
	http.HandleFunc("/login", LoginUser)
	http.HandleFunc("/register", RegisterUser)
	http.HandleFunc("/logout", LogoutUser)

	// Rutas protegidas (requieren autenticación)
	http.HandleFunc("/", AuthMiddleware(ListItems))
	http.HandleFunc("/create", AuthMiddleware(CreateItem))
	http.HandleFunc("/edit", AuthMiddleware(EditItem))
	http.HandleFunc("/delete", AuthMiddleware(DeleteItem))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Servidor en ejecución en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Obtén la cookie "user_uid"
		cookie, err := r.Cookie("user_uid")
		if err != nil || cookie.Value == "" {
			// Si no hay cookie o está vacía, redirige al login
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Verifica el UID en Firebase (opcional)
		_, err = authClient.GetUser(context.Background(), cookie.Value)
		if err != nil {
			// Si el UID no es válido, redirige al login
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Si el usuario está autenticado, continúa con la solicitud
		next(w, r)
	}
}

func ListItems(w http.ResponseWriter, r *http.Request) {
	// Configura cabeceras para evitar el caché
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1
	w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0
	w.Header().Set("Expires", "0")                                         // Proxies

	ctx := context.Background()
	var items []map[string]interface{}
	docs, err := client.Collection("items").Documents(ctx).GetAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, doc := range docs {
		item := doc.Data()
		item["ID"] = doc.Ref.ID
		items = append(items, item)
	}
	tmpl.ExecuteTemplate(w, "index.html", items)
}

func CreateItem(w http.ResponseWriter, r *http.Request) {
	// Configura cabeceras para evitar el caché
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if r.Method == http.MethodPost {
		ctx := context.Background()
		r.ParseForm()
		_, _, err := client.Collection("items").Add(ctx, map[string]interface{}{
			"name":        r.FormValue("name"),
			"description": r.FormValue("description"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	tmpl.ExecuteTemplate(w, "create.html", nil)
}

func EditItem(w http.ResponseWriter, r *http.Request) {
	// Configura cabeceras para evitar el caché
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID no proporcionado", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	doc, err := client.Collection("items").Doc(id).Get(ctx)
	if err != nil {
		http.Error(w, "Elemento no encontrado", http.StatusNotFound)
		return
	}

	item := doc.Data()
	item["ID"] = id

	if r.Method == http.MethodPost {
		r.ParseForm()
		_, err := client.Collection("items").Doc(id).Set(ctx, map[string]interface{}{
			"name":        r.FormValue("name"),
			"description": r.FormValue("description"),
		})
		if err != nil {
			http.Error(w, "Error actualizando", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	tmpl.ExecuteTemplate(w, "edit.html", item)
}

func DeleteItem(w http.ResponseWriter, r *http.Request) {
	// Configura cabeceras para evitar el caché
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID no proporcionado", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	_, err := client.Collection("items").Doc(id).Delete(ctx)
	if err != nil {
		http.Error(w, "Error eliminando el elemento", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		params := (&auth.UserToCreate{}).
			Email(email).
			Password(password)

		user, err := authClient.CreateUser(context.Background(), params)
		if err != nil {
			http.Error(w, "Error registrando usuario", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Usuario registrado: %s", user.Email)
		return
	}
	http.ServeFile(w, r, "templates/register.html")
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		idToken := r.FormValue("idToken")
		fmt.Println("Token recibido:", idToken) // Debug

		// Verifica el token
		token, err := authClient.VerifyIDToken(context.Background(), idToken)
		if err != nil {
			fmt.Println("Error verificando token:", err) // Debug
			http.Error(w, "Token inválido", http.StatusUnauthorized)
			return
		}

		fmt.Println("Usuario autenticado con UID:", token.UID) // Debug

		// Almacena el UID en una cookie
		http.SetCookie(w, &http.Cookie{
			Name:  "user_uid",
			Value: token.UID,
			Path:  "/",
		})

		// Redirige al usuario a la página principal
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, "templates/login.html") // Sirve la página de login
}

func LogoutUser(w http.ResponseWriter, r *http.Request) {
	// Elimina la cookie "user_uid"
	http.SetCookie(w, &http.Cookie{
		Name:   "user_uid",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Elimina la cookie
	})

	// Redirige al usuario a la página de login con un parámetro para forzar la recarga
	http.Redirect(w, r, "/login?reload=true", http.StatusSeeOther)
}

func APIListItems(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var items []map[string]interface{}
	docs, err := client.Collection("items").Documents(ctx).GetAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, doc := range docs {
		item := doc.Data()
		item["ID"] = doc.Ref.ID
		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func CheckAuth(w http.ResponseWriter, r *http.Request) {
	// Obtén la cookie "user_uid"
	cookie, err := r.Cookie("user_uid")
	if err != nil || cookie.Value == "" {
		// Si no hay cookie o está vacía, el usuario no está autenticado
		w.WriteHeader(http.StatusUnauthorized) // Responde con un código 401 (No autorizado)
		return
	}

	// Verifica el UID en Firebase (opcional)
	_, err = authClient.GetUser(context.Background(), cookie.Value)
	if err != nil {
		// Si el UID no es válido, el usuario no está autenticado
		w.WriteHeader(http.StatusUnauthorized) // Responde con un código 401 (No autorizado)
		return
	}

	// Si el usuario está autenticado, responde con un código 200 (OK)
	w.WriteHeader(http.StatusOK)
}
