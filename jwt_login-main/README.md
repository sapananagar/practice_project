# 🔐 Auth Service — Spring Boot + JWT + PostgreSQL

A complete authentication service with Register, Login, JWT Access/Refresh Tokens,
and Role-Based Access Control (RBAC). Built with Spring Boot 3, Spring Security 6,
and PostgreSQL.

---

## 📁 Project Structure

```
src/main/java/com/example/authservice/
├── AuthServiceApplication.java       ← Entry point (main method)
├── config/
│   ├── SecurityConfig.java           ← Spring Security rules + beans
│   └── GlobalExceptionHandler.java   ← Clean JSON error responses
├── controller/
│   └── AuthController.java           ← REST endpoints
├── dto/
│   └── AuthDto.java                  ← Request/Response shapes
├── entity/
│   ├── User.java                     ← "users" DB table + UserDetails
│   └── Role.java                     ← USER, ADMIN enum
├── repository/
│   └── UserRepository.java           ← DB queries (Spring Data JPA)
├── security/
│   ├── JwtUtil.java                  ← JWT creation + validation
│   └── JwtAuthFilter.java            ← Reads JWT on every request
└── service/
    └── AuthService.java              ← Business logic
```

---

## 🐘 Setting Up PostgreSQL

### Option A — Docker (easiest for local dev)
```bash
docker run --name auth-postgres \
  -e POSTGRES_PASSWORD=yourpassword \
  -e POSTGRES_DB=authdb \
  -p 5432:5432 \
  -d postgres:16
```

### Option B — Local PostgreSQL install
```sql
-- Run in psql
CREATE DATABASE authdb;
GRANT ALL PRIVILEGES ON DATABASE authdb TO postgres;
```

### Update credentials in application.properties
```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/authdb
spring.datasource.username=postgres
spring.datasource.password=yourpassword
```

---

## 🚀 Running the Project

```bash
mvn spring-boot:run
```
Server: http://localhost:8080

---

## 🧪 Testing the API

### 1. Register
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"firstName":"Priya","lastName":"Sharma","email":"priya@example.com","password":"securepass123"}'
```
**Response 201:** `{ "accessToken":"...", "refreshToken":"...", "expiresIn":900, "user":{...} }`

### 2. Login
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"priya@example.com","password":"securepass123"}'
```

### 3. Access protected endpoint
```bash
curl http://localhost:8080/api/user/me \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>"
```

### 4. Refresh token (after 15-min access token expires)
```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<YOUR_REFRESH_TOKEN>"}'
```

### 5. Test RBAC — Admin endpoint
```bash
curl http://localhost:8080/api/admin/dashboard \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>"
# Returns 403 for ROLE_USER. To test admin:
# UPDATE users SET role = 'ADMIN' WHERE email = 'priya@example.com';
```

---

## 🔑 RBAC — Role-Based Access Control

Two levels of enforcement:

**1. URL-level (SecurityConfig.java)**
```java
.requestMatchers("/api/admin/**").hasRole("ADMIN")
.anyRequest().authenticated()
```

**2. Method-level (AuthController.java)**
```java
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> adminDashboard() { ... }
```

---

## 🔐 Production Checklist

- [ ] Replace `jwt.secret` → `openssl rand -base64 64`
- [ ] Set `ddl-auto=validate`, use Flyway for DB migrations
- [ ] Move DB credentials to environment variables
- [ ] Enable HTTPS
- [ ] Store refresh tokens in DB to support logout/revocation
- [ ] Add rate limiting on /login and /register

---

## 📚 Key Concepts

| Question | Answer |
|---|---|
| Why BCrypt? | Intentionally slow — brute-force takes years |
| Why two tokens? | Short-lived access = less damage if stolen; refresh = stay logged in |
| What is `UserDetails`? | Spring Security interface your `User` entity implements |
| What is `SecurityContext`? | Per-request holder for "who is logged in right now" |
| Why `@Transactional`? | If anything fails, the whole DB write is rolled back |
| What is `JpaRepository`? | Spring Data interface — gives `save()`, `findById()`, etc. for free |
