# Translation glossary

Agreed terms for the admin UI. Keep them consistent across every string; if you
change a term, change it everywhere in that locale. **Never translate** product,
protocol and identifier names: Zoraxy, ACME, TLS, SSL, OIDC, OAuth2, SSO, HTTP, HTTPS,
HTTP/2, WebSocket, DNS, CAPTCHA (brand words: Turnstile, reCAPTCHA, Altcha, Friendly Captcha),
WAF (the acronym stays; the long form may be spelled out once), CIDR, IP, CORS, JWT, API,
GeoIP, Docker, Lua, Prometheus, Let's Encrypt, Cloudflare, Authentik, zrok, Sablier, ECH, mTLS,
CSV, JSON, YAML, UUID, CPU, RAM. Keep `{0}` / `{1}` placeholders, HTML-like fragments, units
(ms, s, MB) and emoji exactly as in the source.

| English | zh-CN 简体中文 | zh-TW 繁體中文 | es | de | fr | ja | pt-BR | ru |
|---|---|---|---|---|---|---|---|---|
| proxy rule | 代理规则 | 代理規則 | regla de proxy | Proxy-Regel | règle de proxy | プロキシルール | regra de proxy | правило прокси |
| reverse proxy | 反向代理 | 反向代理 | proxy inverso | Reverse-Proxy | proxy inverse | リバースプロキシ | proxy reverso | обратный прокси |
| upstream | 上游 | 上游 | upstream (origen) | Upstream | amont (upstream) | アップストリーム | upstream | апстрим |
| virtual directory | 虚拟目录 | 虛擬目錄 | directorio virtual | virtuelles Verzeichnis | répertoire virtuel | 仮想ディレクトリ | diretório virtual | виртуальный каталог |
| certificate | 证书 | 憑證 | certificado | Zertifikat | certificat | 証明書 | certificado | сертификат |
| private key | 私钥 | 私密金鑰 | clave privada | privater Schlüssel | clé privée | 秘密鍵 | chave privada | закрытый ключ |
| WAF (web application firewall) | WAF（Web 应用防火墙） | WAF（網站應用程式防火牆） | WAF (cortafuegos de aplicaciones web) | WAF (Web Application Firewall) | WAF (pare-feu applicatif web) | WAF（Webアプリケーションファイアウォール） | WAF (firewall de aplicações web) | WAF (межсетевой экран веб-приложений) |
| rate limit | 速率限制 | 速率限制 | límite de tasa | Ratenbegrenzung | limite de débit | レート制限 | limite de taxa | ограничение частоты запросов |
| access rule | 访问规则 | 存取規則 | regla de acceso | Zugriffsregel | règle d'accès | アクセスルール | regra de acesso | правило доступа |
| blocklist / allowlist | 黑名单 / 白名单 | 黑名單 / 白名單 | lista de bloqueo / lista de permitidos | Sperrliste / Zulassungsliste | liste de blocage / liste d'autorisation | ブロックリスト / 許可リスト | lista de bloqueio / lista de permissões | список блокировки / список разрешённых |
| blocked / allowed | 已拦截 / 已允许 | 已封鎖 / 已允許 | bloqueado / permitido | blockiert / erlaubt | bloqué / autorisé | ブロック / 許可 | bloqueado / permitido | заблокировано / разрешено |
| redirection | 重定向 | 重新導向 | redirección | Weiterleitung | redirection | リダイレクト | redirecionamento | перенаправление |
| stream proxy (TCP/UDP) | 流代理 | 串流代理 | proxy de flujo | Stream-Proxy | proxy de flux | ストリームプロキシ | proxy de fluxo | потоковый прокси |
| load balancing | 负载均衡 | 負載平衡 | balanceo de carga | Lastverteilung | répartition de charge | 負荷分散 | balanceamento de carga | балансировка нагрузки |
| health check | 健康检查 | 健康檢查 | comprobación de estado | Integritätsprüfung | contrôle de santé | ヘルスチェック | verificação de integridade | проверка работоспособности |
| hostname / domain | 主机名 / 域名 | 主機名稱 / 網域 | nombre de host / dominio | Hostname / Domain | nom d'hôte / domaine | ホスト名 / ドメイン | nome de host / domínio | имя хоста / домен |
| subdomain | 子域名 | 子網域 | subdominio | Subdomain | sous-domaine | サブドメイン | subdomínio | поддомен |
| alias | 别名 | 別名 | alias | Alias | alias | エイリアス | alias | псевдоним |
| tag | 标签 | 標籤 | etiqueta | Tag | étiquette | タグ | tag | тег |
| default site | 默认站点 | 預設網站 | sitio predeterminado | Standardseite | site par défaut | デフォルトサイト | site padrão | сайт по умолчанию |
| settings | 设置 | 設定 | configuración | Einstellungen | paramètres | 設定 | configurações | настройки |
| status | 状态 | 狀態 | estado | Status | état | ステータス | status | состояние |
| security center | 安全中心 | 安全中心 | centro de seguridad | Sicherheitszentrale | centre de sécurité | セキュリティセンター | central de segurança | центр безопасности |
| logs | 日志 | 日誌 | registros | Protokolle | journaux | ログ | logs | журналы |
| plugin | 插件 | 外掛 | complemento | Plugin | extension (plugin) | プラグイン | plugin | плагин |
| API token | API 令牌 | API 權杖 | token de API | API-Token | jeton d'API | APIトークン | token de API | токен API |
| trusted proxy | 受信任代理 | 受信任的代理 | proxy de confianza | vertrauenswürdiger Proxy | proxy de confiance | 信頼されたプロキシ | proxy confiável | доверенный прокси |
| client IP | 客户端 IP | 用戶端 IP | IP del cliente | Client-IP | IP du client | クライアントIP | IP do cliente | IP клиента |
| enable / disable | 启用 / 禁用 | 啟用 / 停用 | activar / desactivar | aktivieren / deaktivieren | activer / désactiver | 有効化 / 無効化 | ativar / desativar | включить / отключить |
| save / apply / cancel | 保存 / 应用 / 取消 | 儲存 / 套用 / 取消 | guardar / aplicar / cancelar | Speichern / Übernehmen / Abbrechen | enregistrer / appliquer / annuler | 保存 / 適用 / キャンセル | salvar / aplicar / cancelar | сохранить / применить / отмена |
| delete / remove | 删除 / 移除 | 刪除 / 移除 | eliminar / quitar | löschen / entfernen | supprimer / retirer | 削除 / 取り除く | excluir / remover | удалить / убрать |
| dashboard | 仪表盘 | 儀表板 | panel | Dashboard | tableau de bord | ダッシュボード | painel | панель |
| request / response | 请求 / 响应 | 請求 / 回應 | solicitud / respuesta | Anfrage / Antwort | requête / réponse | リクエスト / レスポンス | requisição / resposta | запрос / ответ |
| visitor | 访客 | 訪客 | visitante | Besucher | visiteur | 訪問者 | visitante | посетитель |
| fleet (central management) | 集群管理（Fleet） | 叢集管理（Fleet） | flota | Flotte | flotte | フリート | frota | флот |
| high availability / cluster | 高可用 / 集群 | 高可用 / 叢集 | alta disponibilidad / clúster | Hochverfügbarkeit / Cluster | haute disponibilité / cluster | 高可用性 / クラスター | alta disponibilidade / cluster | высокая доступность / кластер |

## Style

* zh-CN: simplified characters, mainland IT vocabulary (服务器, 默认, 设置); no spaces between CJK and numbers unless the source has them; use full-width punctuation in sentences, keep half-width in code-like text.
* zh-TW: Taiwan vocabulary (伺服器, 預設, 設定, 憑證, 使用者); never copy zh-CN wording that differs.
* de: formal "Sie"-free imperative / noun style as in typical admin UIs ("Speichern", "Regel hinzufügen"); keep compound nouns reasonable in length; the nav has little space so prefer short words.
* fr: infinitive for buttons ("Enregistrer"), "vous" for sentences.
* es: neutral Latin-American/Spain-compatible, "usted" avoided (infinitive for buttons).
* ja: です/ます in sentences, buttons as noun forms (保存, 追加, 削除).
* pt-BR: Brazilian spelling ("arquivo", "usuário"), infinitive for buttons.
* ru: infinitive for buttons ("Сохранить"), formal "вы" lower-case.
* Keep buttons and table headers as short as the English source: the layout has little room.
