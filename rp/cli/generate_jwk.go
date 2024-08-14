package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func main() {
	// 鍵を保存するディレクトリ
	keysDir := "keys"

	// ディレクトリが存在するか確認
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		log.Fatalf("ディレクトリ '%s' が存在しません。", keysDir)
	}

	// 公開鍵と秘密鍵のパス
	publicKeyPath := fmt.Sprintf("%s/public_key.pem", keysDir)
	privateKeyPath := fmt.Sprintf("%s/private_key.pem", keysDir)

	// 公開鍵の読み込み
	publicKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatalf("公開鍵の読み込みに失敗しました: %v", err)
	}

	// 公開鍵をJWKに変換
	publicJWK, err := jwk.ParseKey(publicKeyData, jwk.WithPEM(true))
	if err != nil {
		log.Fatalf("公開鍵をJWKに変換できませんでした: %v", err)
	}

	// 秘密鍵の読み込み
	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("秘密鍵の読み込みに失敗しました: %v", err)
	}

	// 秘密鍵をJWKに変換
	privateJWK, err := jwk.ParseKey(privateKeyData, jwk.WithPEM(true))
	if err != nil {
		log.Fatalf("秘密鍵をJWKに変換できませんでした: %v", err)
	}

	// 同じkidを生成して設定
	kid := uuid.New().String()
	publicJWK.Set("kid", kid)
	privateJWK.Set("kid", kid)

	// これつけないとHydraがエラーになる
	publicJWK.Set("use", "sig")

	// 公開鍵JWKをJSON形式で保存
	publicJWKPath := fmt.Sprintf("%s/public_key.jwk", keysDir)
	if err := saveJWK(publicJWK, publicJWKPath); err != nil {
		log.Fatalf("公開鍵JWKの保存に失敗しました: %v", err)
	}

	// 秘密鍵JWKをJSON形式で保存
	privateJWKPath := fmt.Sprintf("%s/private_key.jwk", keysDir)
	if err := saveJWK(privateJWK, privateJWKPath); err != nil {
		log.Fatalf("秘密鍵JWKの保存に失敗しました: %v", err)
	}

	fmt.Printf("JWKファイルが '%s' および '%s' に保存されました。\n", publicJWKPath, privateJWKPath)
}

// saveJWKはJWKを指定されたパスに保存するヘルパー関数です。
func saveJWK(key jwk.Key, path string) error {
	// JWKをJSON形式にエンコード
	jwkJSON, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("JWKのJSONエンコードに失敗しました: %w", err)
	}

	// ファイルに書き込む
	if err := os.WriteFile(path, jwkJSON, 0600); err != nil {
		return fmt.Errorf("ファイルへの書き込みに失敗しました: %w", err)
	}

	return nil
}
