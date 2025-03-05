package api

import (
	"context"
	"encoding/json"
	"net/http"

	"cloud.google.com/go/firestore"
)

var client *firestore.Client

// Inicializa el cliente de Firestore
func Init(firestoreClient *firestore.Client) {
	client = firestoreClient
}

// Obtener todos los elementos (GET /api/items)
func ListItems(w http.ResponseWriter, r *http.Request) {
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

// Crear un nuevo elemento (POST /api/items)
func CreateItem(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var item map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, _, err := client.Collection("items").Add(ctx, item)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Elemento creado correctamente"})
}

// Actualizar un elemento existente (PUT /api/items)
func UpdateItem(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID no proporcionado", http.StatusBadRequest)
		return
	}

	var item map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := client.Collection("items").Doc(id).Set(ctx, item)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Elemento actualizado correctamente"})
}

// Eliminar un elemento (DELETE /api/items)
func DeleteItem(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID no proporcionado", http.StatusBadRequest)
		return
	}

	_, err := client.Collection("items").Doc(id).Delete(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Elemento eliminado correctamente"})
}
