# くすぶるガイド 修正・デプロイ手順書

## フォルダ構成
```
kusuburu-guide/
├── index.html              ← 本番（GitHub Pagesで公開）
├── checkin.html             ← 本番
├── welcome.html             ← 本番
├── admin-k7x2m9f4.html     ← 本番
├── demo/                    ← 修正・確認用（ローカル専用・pushされない）
├── backup/                  ← 本番反映直前のバックアップ（pushされない）
└── worker/                  ← Cloudflare Worker
```

## 修正・アップデート手順

### Step 1: demo/ で修正
demo/ フォルダ内のファイルを編集する。本番ファイルは絶対に直接触らない。

### Step 2: ローカルで確認
ブラウザでdemo/のHTMLを開いて動作確認。スマホ表示もチェック。

### Step 3: backup/ に現在の本番をバックアップ
```bash
cp index.html backup/index.html
cp checkin.html backup/checkin.html
cp welcome.html backup/welcome.html
cp admin-k7x2m9f4.html backup/admin-k7x2m9f4.html
```

### Step 4: demo/ → 本番にコピー
```bash
cp demo/index.html index.html
cp demo/checkin.html checkin.html
cp demo/welcome.html welcome.html
cp demo/admin-k7x2m9f4.html admin-k7x2m9f4.html
```

### Step 5: push
```bash
git add -A
git commit -m "内容の説明"
git push
```

### Step 6: 本番確認
https://kusuburu.okikoubou.com/ で動作確認

### Step 7: 問題があれば即復元
```bash
cp backup/checkin.html checkin.html
（必要なファイルをbackupから復元）
git add -A && git commit -m "revert: 問題があったため復元" && git push
```

## Worker変更時の注意

- HTMLだけの変更 → git pushだけ（低リスク）
- Workerの変更 → `wrangler dev`でローカルテスト → `wrangler deploy`
- 両方変更 → Worker先にデプロイ → 動作確認 → HTML push

## やってはいけないこと
- 本番ファイルを直接編集してpush
- backupを取らずに本番反映
- D1のスキーマ変更を気軽にやる（既存データが消える可能性）
- フロントとWorkerを同時にデプロイ
