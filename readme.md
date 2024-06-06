# Keycloak with dotnet

```
docker compose build
docker compose up -d
```

開啟 http://localhost:5000/swagger/index.html ， 按下 「Authoriz」按鈕，再按下 「Authorize」會導向 Keycloak 登入頁面，輸入帳號密碼後，會取得 Token，再回到 Swagger 頁面，將 Token 貼到上方的輸入框，即可使用 API。

## info 
account: admin
password: admin


