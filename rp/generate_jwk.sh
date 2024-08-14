#!/bin/bash

# エラーハンドリング
set -e
trap 'echo "エラーが発生しました。スクリプトを終了します。"; exit 1' ERR

# 鍵を保存するディレクトリ
KEYS_DIR="keys"

# 1. keysディレクトリの作成（存在しない場合）
if [ ! -d "$KEYS_DIR" ]; then
  echo "ディレクトリ '$KEYS_DIR' を作成しています..."
  mkdir "$KEYS_DIR"
else
  echo "ディレクトリ '$KEYS_DIR' は既に存在します。"
fi

# 2. RSA鍵ペアの生成
echo "RSA鍵ペアを生成しています..."
openssl genpkey -algorithm RSA -out "$KEYS_DIR/private_key.pem" -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in "$KEYS_DIR/private_key.pem" -out "$KEYS_DIR/public_key.pem"
chmod 600 "$KEYS_DIR/private_key.pem"
echo "RSA鍵ペアが '$KEYS_DIR' ディレクトリに生成されました。"

# 3. JWK化
go run ./cli/generate_jwk.go