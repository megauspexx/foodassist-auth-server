# foodassist-auth

Минимальный Go-сервер с двумя эндпоинтами:

- `POST /auth/google` — принимает `idToken` от Google Sign-In, проверяет подпись/issuer/audience через JWKS Google, создаёт/находит пользователя, возвращает свою session JWT.
- `POST /auth/apple` — принимает `identityToken` от Sign in with Apple, проверяет подпись/issuer/audience через JWKS Apple, создаёт/находит пользователя, возвращает свою session JWT.

## Запуск

```bash
cp .env.example .env
# заполнить GOOGLE_CLIENT_ID, APPLE_BUNDLE_ID, JWT_SECRET

go mod tidy
export $(cat .env | xargs)   # или используйте direnv/godotenv
go run .
```

Сервер поднимется на `:8080` (или на порту из `PORT`).

## Проверка

```bash
curl -X POST localhost:8080/auth/google \
  -H "Content-Type: application/json" \
  -d '{"idToken":"<реальный idToken с клиента>"}'

curl -X POST localhost:8080/auth/apple \
  -H "Content-Type: application/json" \
  -d '{"identityToken":"<реальный identityToken с клиента>","userId":"...","email":"...","name":"..."}'
```

Успешный ответ у обоих одинаковой формы:

```json
{
  "token": "<JWT сессии>",
  "user": { "id": "...", "name": "...", "email": "...", "provider": "google" }
}
```

## Важные детали

- **Google**: `GOOGLE_CLIENT_ID` должен быть Web-типа из Google Cloud Console — тот же, что передаётся как `webClientId` в `GoogleSignin.configure()` на клиенте. Сервер проверяет, что `aud` токена совпадает с ним.
- **Apple**: `APPLE_BUNDLE_ID` — это bundle id вашего iOS-приложения. Сервер проверяет, что `aud` токена совпадает с ним. Apple присылает `email`/полное имя **только при самом первом входе** — дальше их нет ни в токене, ни от клиента, поэтому их нужно сохранить у себя при первом визите (уже реализовано в `store.MemoryStore.FindOrCreate`).
- **Хранилище пользователей** сейчас — `internal/store.MemoryStore`, данные живут только в памяти и пропадают при рестарте. Это заглушка для разработки. Когда будет готова БД — реализуйте интерфейс `store.Store` (один метод `FindOrCreate`) поверх Postgres/MySQL/etc и подставьте в `main.go` вместо `store.NewMemoryStore()`. Остальной код менять не придётся.
- **Session JWT** подписывается HS256 с `JWT_SECRET` и живёт 30 дней (`SessionTTL` в `internal/config`). Для защищённых роутов позже используйте `auth.SessionManager.ParseToken` как middleware.
- **CORS** сейчас открыт (`*`) для удобства разработки — сузьте `Access-Control-Allow-Origin` в `main.go` перед продакшеном.
- JWKS Google/Apple кешируются в памяти на 1 час (`internal/jwks`), лишних запросов на каждый логин не будет.

## Структура

```
main.go                        // роутинг, старт сервера
internal/config/config.go      // чтение переменных окружения
internal/auth/google.go        // верификация Google idToken
internal/auth/apple.go         // верификация Apple identityToken
internal/auth/session.go       // выпуск/проверка собственной session JWT
internal/jwks/jwks.go          // общий кеш JWKS (используется и Google, и Apple)
internal/store/user.go         // интерфейс Store + in-memory реализация
internal/handlers/auth.go      // HTTP-хендлеры /auth/google и /auth/apple
```
