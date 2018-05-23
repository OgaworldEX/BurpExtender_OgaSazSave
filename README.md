# BurpExtender_OgaSazSave

BurpSuiteから[Fiddler](https://www.telerik.com/fiddler)のログ形式であるSAZ(Session Archive)を出力するExtentionです。

## Usage
BurpSuite の Python Extensionとしてロードしてください。

出力先はc:\tmp固定です。存在しない場合は作成してください。

Historyなど保存したい場所で右クリックの「Send to OgaSazSave」を選択して保存します。


## 既知の問題
リクエストにバイナリなどchr()で変換できないバイトが含まれていた場合、エラーになります。
