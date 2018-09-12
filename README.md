# privacy-exposer

privacy-exposerは宛先に応じて上流のSOCKS5やHTTPプロクシへ中継する機能を持つSOCKS5プロクシです。CONNECTコマンドのみに対応します。

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
privacy-exposer [-p pidfile] [-l loglevel] [-r rule-config] [bind-addr bind-port]
```

`-r`で、宛先に応じたプロクシ接続のルールが書かれたファイルを指定します。書式は以下のサンプルを見て雰囲気を感じ取ってください。

```
; セミコロン以降はコメント
; ルールは上から順番に検査されます

; 宛先ホスト末尾が.onionの場合はlocalhost:9050へsocks5で接続
host  .onion          socks5        localhost    9050

; 宛先ホスト末尾が.i2p且つポートが80の場合は192.168.3.1:4447へsocks5で接続
host  .i2p       #80  socks5        192.168.3.1  4447

; 宛先ホストがlocalhostに一致するときは接続を拒否
host  localhost       deny

; 宛先ホストがfoo.exampleに一致するときはこのサーバーから直接接続
host  foo.example

; 宛先が任意のホストでポートが80または443のときは[2001:db8::1]:8118へHTTP CONNETCTで接続
host  #80,443         http-connect  2001:db8::1  8118

; 任意の宛先、任意のポートのときは接続を拒否
all                   deny
```

`-p`を指定すると`pidfile`にPIDを書き込んだ上でデーモン化します。

## 名称について

privacy-exposerは通常のプロクシとして振る舞いつつTor/I2P上のサイトに対してのみそれらのプロクシへ中継させたいという動機から作られました。通常の用途でこのような動作をするプロクシを使うと、互いのネットワーク同士で秘匿すべき情報がクライアントでは分け隔てなく取り扱えることとなり、重大な情報漏洩に繋がる可能性があります。その可能性を示唆するものとしてprivacy-expoerという名称が付けられています。

現在では、Tor/I2Pと固定的だったルールを自由に変えられるようになり、それら秘匿サービスに依らない振り分けが出来るプロクシとして作られています。

## ライセンス

MITライセンス
