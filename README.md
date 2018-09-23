# privacy-exposer

privacy-exposerは宛先に応じて上流のSOCKS5やHTTPプロクシへ中継する機能を持つSOCKS5プロクシです。CONNECTコマンドのみに対応します。

## 特徴

* サーバーとしてSOCKS5、SOCKS4Aに対応します。中継のためのプロクシクライアントとしてはSOCKS5、SOCKS4A、HTTP CONNECTに対応します。
* 宛先と使用するプロクシの組み合わせのルールを簡単に何個でも指定できます。
* 接続毎で使用するプロクシは1つだけではなく、そこから別のプロクシへと連鎖的に繋ぐことが出来ます。
* ルールは中継プロクシ選択だけではなく接続拒否をすることが出来、簡易的なコンテンツフィルタとしても使うことが出来ます。
* 再起動することなくルールファイルを再読込させることが出来、その間の接続は切断されることなく維持させることが出来ます。プロクシのリストが頻繁に更新される環境で便利です。
* 名前解決の上ではデュアルスタックになっているがIPv6接続に問題があり長時間待たされるというよくある状況に対処するため、接続確立までのタイムアウト時間を短めに設定しています。クライアントがタイムアウトによりクロールを諦める確率を減らすことが期待できます。

## コンパイル・動作要件

* C99
* POSIX.1-2008
* `vsyslog()`が公開されること。NetBSDでは`CFLAGS`に`-D_NETBSD_SOURCE`の追加が必要。

## コンパイル・インストール方法

```
CFLAGS=-DNDEBUG make
```

をすると`privacy-expoer`が出力されるので、それを任意の場所にコピーします。

## 使い方

次のコマンドでSOCKS5サーバーが起動します。`bind-addr`、`bind-port`が省略されたときの初期値はそれぞれ`localhost`、`9000`です。

```
privacy-exposer [-p pidfile] [-l loglevel] [-r rule-config] [bind-addr bind-port]...
```

`-r`で、宛先に応じたプロクシ接続のルールが書かれたファイルを指定します。書式は[ウィキ](https://github.com/hcmiya/privacy-exposer/wiki/%E3%83%AB%E3%83%BC%E3%83%AB%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB%E6%96%87%E6%B3%95)を参照してください。以下に使用例を示します。

```
; セミコロン以降はコメント
; ルールは上から順番に検査されます

; 宛先ドメインがonionの場合、言い換えるとTLDがonionの場合はlocalhost:9050へsocks5で接続
domain  onion  socks5  localhost  9050

; 宛先ドメインがi2p且つポートが80の場合は192.168.3.1:4447へsocks5で接続
domain  i2p  #80  socks5  192.168.3.1  4447

; 宛先ホストがlocalhostや、名前解決後を含むネットワークがループバックアドレスに一致するときは接続を拒否
net6-resolve  ::1/128  deny
net4-resolve  127.0.0.0/8  deny
host  localhost  deny

; 宛先ドメインがfunimation.exampleの場合、localhost:9050へsock5で接続した後
; さらにus.proxy.example:8080へHTTP CONNETCTで接続
domain  funimation.example  socks5  localhost  9050  http-connect  us.proxy.example  8080
```

`-p`を指定すると`pidfile`にPIDを書き込んだ上でデーモン化します。

その他オプションは[マニュアル](https://github.com/hcmiya/privacy-exposer/wiki/privacy-exposer%E3%83%9E%E3%83%8B%E3%83%A5%E3%82%A2%E3%83%AB)を参照してください。

## 名称について

privacy-exposerは、通常のプロクシとして振る舞いつつTor/I2P上のサイトに対してはそれらのプロクシへ中継させるようにし、プロクシの設定を1つしか持てない自動巡回プログラムで使わせるようにしたい、という動機から作られました。通常のブラウジング用途でこのような動作をするプロクシを使うと、互いのネットワーク同士で秘匿すべき情報がクライアントでは分け隔てなく取り扱えることとなり、重大な情報漏洩に繋がる可能性があります。その可能性を示唆するものとしてprivacy-exposerという名称が付けられています。

現在では、Tor/I2Pと固定的だったルールを自由に変えられるようになり、それら秘匿サービスに依らない振り分けが出来るプロクシとして作られています。

privacy-exposer自体にコンピューターの機密情報を抜き出すようなエクスプロイトが仕掛けられているわけではありません。

## ライセンス

MITライセンス
